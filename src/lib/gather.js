// Collects the facts the diagnosis is built from. Everything here only looks: no setting is
// changed, nothing needs admin rights, and the only outside addresses contacted are in targets.js.
import os from "node:os";
import fs from "node:fs";
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns";
import crypto from "node:crypto";

import { run } from "./run.js";
import {
  parsePing,
  parseProcRoute,
  parseNetstatDarwin,
  parseRoutePrintWin,
  parseMacAirport,
  parseNetshWlan,
  parseNetshNetworks,
  parseWifiAdapters,
  parseNmcli,
  parseIwLink,
  parseProcWireless,
  freqToChannel,
  percentToDbm,
} from "./parse.js";
import { INTERNET_HOSTS, PUBLIC_DNS, KNOWN_NAME, MISSING_NAME_DOMAIN, CAPTIVE_URL, HTTPS_HOST, IPV6_HOST, USER_AGENT } from "./targets.js";

const PLATFORM = process.platform;
const now = () => performance.now();
const round = (n, d = 1) => (n === null || n === undefined ? null : Math.round(n * 10 ** d) / 10 ** d);

// ---------- interfaces and VPNs -------------------------------------------------------------

const VPN_NAME =
  /^(utun|tun|tap|wg|ppp|ipsec|tailscale|zt|nordlynx|proton|mullvad|cscotun|gpd)|vpn|wireguard|tailscale|openvpn|wintun|tap-windows|nordlynx|anyconnect|globalprotect|pangp|zerotier|forti|zscaler|warp/i;

export const isVpnName = (name) => VPN_NAME.test(String(name || ""));

const isGlobalV6 = (a) => !/^(fe80|fc|fd|::1|::$)/i.test(a);

/** Addresses this computer has, without the internal loopback ones. */
export function getInterfaces(ifaces = os.networkInterfaces()) {
  const list = [];
  for (const [name, addrs] of Object.entries(ifaces)) {
    for (const a of addrs || []) {
      if (a.internal) continue;
      list.push({ name, family: a.family === 4 ? "IPv4" : a.family === 6 ? "IPv6" : a.family, address: a.address });
    }
  }
  const v4 = list.filter((a) => a.family === "IPv4");
  const usableV4 = v4.filter((a) => !a.address.startsWith("169.254."));
  const globalV6 = list.filter((a) => a.family === "IPv6" && isGlobalV6(a.address));
  // Tunnels that carry a real address. macOS always has a few utun interfaces with only
  // link-local addresses; those are system plumbing, not a VPN someone turned on.
  const tunnels = [...new Set(list.filter((a) => isVpnName(a.name) && (a.family === "IPv4" || isGlobalV6(a.address))).map((a) => a.name))];
  return {
    list,
    hasAny: usableV4.length > 0 || globalV6.length > 0,
    selfAssignedOnly: v4.length > 0 && usableV4.length === 0 && globalV6.length === 0,
    hasGlobalV6: globalV6.some((a) => !isVpnName(a.name)),
    tunnels,
  };
}

// ---------- routes --------------------------------------------------------------------------

/**
 * Where traffic leaves this computer. Returns
 * { primaryIface, viaVpn, router: { ip, iface } | null, vpnIfaces, error }.
 * The router is the home router: the first default route with a real gateway that is not a VPN.
 */
export async function getRoutes(interfaces = getInterfaces()) {
  const out = { primaryIface: null, viaVpn: false, router: null, vpnIfaces: interfaces.tunnels, error: null };
  try {
    if (PLATFORM === "linux") {
      const rows = parseProcRoute(fs.readFileSync("/proc/net/route", "utf8"));
      const split = rows.find((r) => r.split);
      const defaults = rows.filter((r) => !r.split);
      const primary = split || defaults[0];
      const phys = defaults.find((r) => r.gateway && !isVpnName(r.iface));
      out.primaryIface = primary?.iface || null;
      out.router = phys ? { ip: phys.gateway, iface: phys.iface } : null;
    } else if (PLATFORM === "darwin") {
      const r = await run("netstat", ["-rn", "-f", "inet"], { timeoutMs: 8000 });
      const rows = parseNetstatDarwin(r.stdout);
      const split = rows.find((x) => x.split);
      const primary = split || rows.find((x) => !x.split && !x.scoped) || rows.find((x) => !x.split);
      const phys = rows.find((x) => !x.split && x.gateway && !isVpnName(x.iface));
      out.primaryIface = primary?.iface || null;
      out.router = phys ? { ip: phys.gateway, iface: phys.iface } : null;
    } else if (PLATFORM === "win32") {
      const r = await run("route", ["print", "-4"], { timeoutMs: 8000 });
      const rows = parseRoutePrintWin(r.stdout);
      const byIp = new Map(interfaces.list.filter((a) => a.family === "IPv4").map((a) => [a.address, a.name]));
      const named = rows.map((x) => ({ ...x, iface: byIp.get(x.ifaceIp) || x.ifaceIp }));
      const split = named.find((x) => x.split);
      const primary = split || named.find((x) => !x.split);
      const phys = named.find((x) => !x.split && x.gateway && !isVpnName(x.iface));
      out.primaryIface = primary?.iface || null;
      out.router = phys ? { ip: phys.gateway, iface: phys.iface } : null;
    } else {
      out.error = `This system (${PLATFORM}) is not supported yet.`;
    }
  } catch (e) {
    out.error = e.message;
  }
  out.viaVpn = Boolean(out.primaryIface && isVpnName(out.primaryIface));
  if (out.viaVpn && !out.vpnIfaces.includes(out.primaryIface)) out.vpnIfaces = [...out.vpnIfaces, out.primaryIface];
  return out;
}

// ---------- Wi-Fi ---------------------------------------------------------------------------

/**
 * The Wi-Fi connection, if there is one. Network names are never read or returned.
 * { present, connected, iface, signal (dBm), noise, band, channel, width, phy, rate (Mbps),
 *   neighbors: [{ channel, band }], note }
 */
export async function getWifi() {
  try {
    if (PLATFORM === "darwin") {
      const r = await run("system_profiler", ["-json", "SPAirPortDataType"], { timeoutMs: 20000 });
      if (r.missing || !r.stdout) return { present: false, note: "Could not read the Wi-Fi details on this Mac." };
      return parseMacAirport(r.stdout);
    }
    if (PLATFORM === "win32") {
      const r = await run("netsh", ["wlan", "show", "interfaces"], { timeoutMs: 10000 });
      const w = parseNetshWlan(r.stdout + "\n" + r.stderr);
      if (w.error === "location") {
        // Without location access Windows still says which adapter is the Wi-Fi one (physical
        // medium 9 = 802.11), so the report can tell Wi-Fi from a cable even without the details.
        const a = await run(
          "powershell",
          ["-NoProfile", "-NonInteractive", "-Command", "Get-NetAdapter | Where-Object { $_.NdisPhysicalMedium -eq 9 -and $_.Status -eq 'Up' } | ForEach-Object { $_.Name }"],
          { timeoutMs: 15000 },
        );
        return {
          present: true,
          connected: null,
          iface: parseWifiAdapters(a.stdout)[0] || null,
          note: "Windows hides Wi-Fi details until location access is on: Settings > Privacy & security > Location, then allow desktop apps.",
        };
      }
      if (!w.present || !w.connected) return { ...w, neighbors: [] };
      const n = await run("netsh", ["wlan", "show", "networks", "mode=bssid"], { timeoutMs: 10000 });
      // The list includes this computer's own access point; drop one entry on its channel.
      const all = parseNetshNetworks(n.stdout);
      const own = all.findIndex((x) => x.channel === w.channel);
      const neighbors = own >= 0 ? all.filter((_, i) => i !== own) : all;
      return { ...w, iface: w.name, neighbors };
    }
    if (PLATFORM === "linux") {
      let wifiIfaces = [];
      try {
        wifiIfaces = fs.readdirSync("/sys/class/net").filter((i) => fs.existsSync(`/sys/class/net/${i}/wireless`) || fs.existsSync(`/sys/class/net/${i}/phy80211`));
      } catch {
        /* no sysfs */
      }
      if (!wifiIfaces.length) return { present: false };
      const nm = await run("nmcli", ["-t", "-f", "IN-USE,CHAN,FREQ,RATE,SIGNAL,DEVICE", "dev", "wifi", "list", "--rescan", "no"], { timeoutMs: 10000 });
      const rows = nm.ok ? parseNmcli(nm.stdout) : [];
      const neighbors = rows.filter((x) => !x.inUse).map(({ channel, band }) => ({ channel, band }));
      for (const iface of wifiIfaces) {
        const link = parseIwLink((await run("iw", ["dev", iface, "link"], { timeoutMs: 8000 })).stdout);
        const mine = rows.find((x) => x.inUse && (x.device === iface || !x.device));
        if (link.connected) {
          const { band, channel } = freqToChannel(link.freq);
          return { present: true, connected: true, iface, signal: link.signal, band, channel, rate: link.rate, phy: null, neighbors };
        }
        if (mine) {
          return {
            present: true,
            connected: true,
            iface,
            signal: percentToDbm(mine.signalPct),
            signalEstimated: true,
            band: mine.band,
            channel: mine.channel,
            rate: mine.rate,
            phy: null,
            neighbors,
          };
        }
        let level = null;
        try {
          level = parseProcWireless(fs.readFileSync("/proc/net/wireless", "utf8")).find((x) => x.iface === iface);
        } catch {
          /* not available */
        }
        if (level) return { present: true, connected: true, iface, signal: level.signal, neighbors };
      }
      return { present: true, connected: false, iface: wifiIfaces[0], neighbors };
    }
  } catch (e) {
    return { present: false, note: `Could not read the Wi-Fi details: ${e.message}` };
  }
  return { present: false };
}

// ---------- reachability --------------------------------------------------------------------

export const stats = (times, sent) => {
  if (!times.length) return { sent, received: 0, loss: sent ? 1 : null, avg: null, min: null, max: null, jitter: null };
  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  const sd = Math.sqrt(times.reduce((a, b) => a + (b - avg) ** 2, 0) / times.length);
  return {
    sent,
    received: times.length,
    loss: sent ? (sent - times.length) / sent : 0,
    avg: round(avg),
    min: round(Math.min(...times)),
    max: round(Math.max(...times)),
    jitter: round(sd),
  };
};

/** Pings an address. Returns stats with method "ping", or null when ping can't be used here. */
export async function ping(ip, count = 10) {
  if (!net.isIP(ip)) return null;
  const args =
    PLATFORM === "win32"
      ? ["-n", String(count), "-w", "1000", ip] // Windows waits this long for every lost reply
      : PLATFORM === "darwin"
        ? ["-n", "-c", String(count), "-W", "2000", ip]
        : ["-n", "-c", String(count), "-W", "2", ip];
  const r = await run("ping", args, { timeoutMs: count * 1000 + 10000 });
  if (r.missing) return null;
  const parsed = parsePing(r.stdout);
  if (!parsed.received && /not permitted|permission denied|operation not permitted/i.test(r.stderr + r.stdout)) return null;
  return { method: "ping", target: ip, ...stats(parsed.times, count) };
}

/** One TCP connection attempt. A refusal still proves the host answered. */
export function tcpConnect(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const t0 = now();
    const sock = net.connect({ host, port });
    const done = (ok, reason) => {
      sock.destroy();
      resolve({ ok, ms: ok ? round(now() - t0) : null, reason });
    };
    sock.setTimeout(timeoutMs, () => done(false, "timeout"));
    sock.once("connect", () => done(true, "open"));
    sock.once("error", (e) => (e.code === "ECONNREFUSED" ? done(true, "refused") : done(false, e.code || e.message)));
  });
}

/**
 * Repeated TCP connections, as a stand-in when ping is not available or not answered. The first
 * round tries every port at once; if none answers, it stops there instead of waiting on each.
 */
export async function tcpProbe(host, ports, count = 5) {
  const first = await Promise.all(ports.map((p) => tcpConnect(host, p, 2500)));
  const hit = first.findIndex((r) => r.ok);
  if (hit < 0) return { method: "tcp", target: host, ...stats([], count) };
  const times = [first[hit].ms];
  for (let i = 1; i < count; i++) {
    const r = await tcpConnect(host, ports[hit], 2500);
    if (r.ok) times.push(r.ms);
  }
  return { method: "tcp", target: host, ...stats(times, count) };
}

/** Router: ping first; when it does not answer pings, see whether it answers on a common port. */
export async function probeRouter(ip) {
  if (!ip) return null;
  const p = await ping(ip);
  if (p && p.received > 0) return p;
  const t = await tcpProbe(ip, [80, 443, 53], 3);
  if (t.received > 0) return { ...t, pingIgnored: Boolean(p) };
  return p || t;
}

/** Internet: ping both public hosts; fall back to TCP 443 when ping can't be used. Returns the better one plus both. */
export async function probeInternet() {
  const results = await Promise.all(INTERNET_HOSTS.map((h) => ping(h.ip)));
  let probes = results.map((r, i) => (r ? { ...r, label: INTERNET_HOSTS[i].label } : null));
  if (probes.every((p) => !p || p.received === 0)) {
    const tcp = await Promise.all(INTERNET_HOSTS.map(async (h) => ({ ...(await tcpProbe(h.ip, [443], 5)), label: h.label })));
    if (tcp.some((t) => t.received > 0) || probes.every((p) => !p)) probes = tcp;
  }
  probes = probes.filter(Boolean);
  const best = [...probes].sort((a, b) => (a.loss ?? 1) - (b.loss ?? 1) || (a.avg ?? 1e9) - (b.avg ?? 1e9))[0] || null;
  return { best, all: probes };
}

// ---------- DNS -----------------------------------------------------------------------------

const median = (a) => {
  if (!a.length) return null;
  const s = [...a].sort((x, y) => x - y);
  return s[Math.floor(s.length / 2)];
};

async function askServer(server, label, kind) {
  const resolver = new dns.promises.Resolver({ timeout: 2500, tries: 1 });
  try {
    resolver.setServers([server]);
  } catch {
    return { server, label, kind, works: false, error: "not a usable address" };
  }
  let works = false;
  let error = null;
  try {
    await resolver.resolve4(KNOWN_NAME);
    works = true;
  } catch (e) {
    error = e.code || e.message;
  }
  const times = [];
  let madeUp = false;
  if (works) {
    for (let i = 0; i < 3; i++) {
      const name = `hnd-${crypto.randomBytes(5).toString("hex")}.${MISSING_NAME_DOMAIN}`;
      const t0 = now();
      try {
        const ans = await resolver.resolve4(name);
        if (ans.length) madeUp = true;
        times.push(now() - t0);
      } catch (e) {
        if (e.code === "ENOTFOUND" || e.code === "ENODATA") times.push(now() - t0);
      }
    }
  }
  return { server, label, kind, works, error, ms: round(median(times)), madeUp };
}

/** This computer's DNS servers next to two public ones, plus one lookup through the system's own resolver. */
export async function checkDns() {
  const mine = dns.getServers().slice(0, 2);
  const t0 = now();
  let system;
  try {
    await dns.promises.lookup(KNOWN_NAME);
    system = { works: true, ms: round(now() - t0) };
  } catch (e) {
    system = { works: false, error: e.code || e.message };
  }
  const servers = await Promise.all([
    ...mine.map((s) => askServer(s, s.startsWith("127.") || s === "::1" ? "this computer's DNS helper" : "your DNS server", "yours")),
    ...PUBLIC_DNS.map((p) => askServer(p.ip, p.label, "public")),
  ]);
  return { system, servers };
}

// ---------- web -----------------------------------------------------------------------------

/**
 * Plain-HTTP request that should come back 204 and empty. A redirect or a page means a sign-in
 * (captive) page or something in between. Also reads the server's clock.
 */
export async function checkCaptive() {
  try {
    const res = await fetch(CAPTIVE_URL, { redirect: "manual", signal: AbortSignal.timeout(6000), headers: { "user-agent": USER_AGENT } });
    const date = Date.parse(res.headers.get("date") || "");
    const clockSkewSec = Number.isFinite(date) ? Math.round((Date.now() - date) / 1000) : null;
    if (res.status === 204) return { state: "clear", clockSkewSec };
    let host = null;
    const loc = res.headers.get("location");
    if (loc) {
      try {
        host = new URL(loc, CAPTIVE_URL).host;
      } catch {
        /* leave null */
      }
    }
    return { state: "portal", status: res.status, host, clockSkewSec };
  } catch (e) {
    return { state: "unknown", error: e.cause?.code || e.name || e.message };
  }
}

const CERT_TROUBLE = new Set([
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "CERT_UNTRUSTED",
]);
const CLOCK_TROUBLE = new Set(["CERT_NOT_YET_VALID", "CERT_HAS_EXPIRED"]);

/** Opens and closes one secure connection. */
export function checkHttps() {
  return new Promise((resolve) => {
    const t0 = now();
    const sock = tls.connect({ host: HTTPS_HOST.ip, port: 443, servername: HTTPS_HOST.servername });
    const done = (r) => {
      sock.destroy();
      resolve(r);
    };
    sock.setTimeout(6000, () => done({ works: false, error: "timeout" }));
    sock.once("secureConnect", () => done({ works: true, ms: round(now() - t0) }));
    sock.once("error", (e) => {
      const code = e.code || e.message;
      done({ works: false, error: code, inspected: CERT_TROUBLE.has(code), clock: CLOCK_TROUBLE.has(code) });
    });
  });
}

/** When this computer has a public IPv6 address: can it actually reach the internet over IPv6? */
export async function checkIpv6(interfaces = getInterfaces()) {
  if (!interfaces.hasGlobalV6) return { has: false };
  const r = await tcpConnect(IPV6_HOST.ip, IPV6_HOST.port, 4000);
  return { has: true, works: r.ok, ms: r.ms, error: r.ok ? null : r.reason };
}

// ---------- all of it -----------------------------------------------------------------------

export async function gatherAll() {
  const started = now();
  const interfaces = getInterfaces();
  const routes = await getRoutes(interfaces);
  const [router, internet, dnsInfo, captive, https, ipv6, wifi] = await Promise.all([
    probeRouter(routes.router?.ip),
    probeInternet(),
    checkDns(),
    checkCaptive(),
    checkHttps(),
    checkIpv6(interfaces),
    getWifi(),
  ]);
  // connected is null when Windows hides the details; the adapter name still says it is Wi-Fi.
  const onWifi = Boolean(wifi.connected !== false && routes.router && wifi.iface && wifi.iface === routes.router.iface);
  return {
    platform: PLATFORM,
    seconds: round((now() - started) / 1000, 0),
    interfaces,
    routes,
    router,
    internet,
    dns: dnsInfo,
    captive,
    https,
    ipv6,
    wifi,
    onWifi,
  };
}
