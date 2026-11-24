// Readers for the output of the system programs in run.js. All pure: text in, plain objects
// out. Where a program's wording is translated (Windows), the readers lean on things that stay
// the same in every language, such as "TTL=", numbers followed by "ms", and table shapes.
import net from "node:net";

const num = (s) => {
  const n = Number(String(s).replace(",", "."));
  return Number.isFinite(n) ? n : null;
};

// ---------- ping ----------------------------------------------------------------------------

/**
 * Reads ping output from Linux, macOS or Windows (any language). Only real echo replies count:
 * lines that carry a TTL and a time. "Destination host unreachable" replies and duplicates do not.
 * Returns { received, times } where times are in milliseconds.
 */
export function parsePing(text) {
  const times = [];
  for (const line of String(text).split(/\r?\n/)) {
    if (!/\bttl[=:]\s*\d+/i.test(line) || /DUP!/.test(line)) continue;
    const m = [...line.matchAll(/([=<])\s*(\d+(?:[.,]\d+)?)\s*ms\b/gi)].pop();
    if (!m) continue;
    const v = num(m[2]);
    if (v === null) continue;
    times.push(m[1] === "<" ? v / 2 : v); // Windows writes "time<1ms" for anything under a millisecond
  }
  return { received: times.length, times };
}

// ---------- default routes ------------------------------------------------------------------

const hexToIPv4 = (hex) => {
  const n = parseInt(hex, 16);
  if (!Number.isFinite(n)) return null;
  return [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255].join(".");
};

/**
 * Linux /proc/net/route. Returns the default routes (and the two halves some VPNs use instead,
 * 0.0.0.0/1 and 128.0.0.0/1), lowest metric first: [{ iface, gateway, metric, split }].
 */
export function parseProcRoute(text) {
  const out = [];
  for (const line of String(text).split("\n").slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 8) continue;
    const [iface, dest, gw, flags, , , metric, mask] = f;
    const up = (parseInt(flags, 16) & 0x1) !== 0;
    if (!up) continue;
    const isDefault = dest === "00000000" && mask === "00000000";
    const isSplit = mask === "00000080" && (dest === "00000000" || dest === "00000080");
    if (!isDefault && !isSplit) continue;
    const gateway = gw === "00000000" ? null : hexToIPv4(gw);
    out.push({ iface, gateway, metric: Number(metric) || 0, split: isSplit });
  }
  return out.sort((a, b) => a.metric - b.metric);
}

/**
 * macOS `netstat -rn -f inet`. Returns the default routes (and the 0/1 + 128.0/1 halves some VPNs
 * use) in table order: [{ gateway (IPv4 or null for link#N), flags, iface, scoped, split }].
 * A scoped line (flag I) is a per-interface default; an unscoped one is what traffic actually takes.
 */
export function parseNetstatDarwin(text) {
  const out = [];
  for (const line of String(text).split("\n")) {
    const f = line.trim().split(/\s+/);
    const split = f[0] === "0/1" || f[0] === "128.0/1";
    if ((f[0] !== "default" && !split) || f.length < 4) continue;
    const [, gw, flags, iface] = f;
    out.push({ gateway: net.isIPv4(gw) ? gw : null, flags, iface, scoped: flags.includes("I"), split });
  }
  return out;
}

/**
 * Windows `route print -4`. Reads rows by shape, not by heading, so any display language works.
 * Returns active routes for 0.0.0.0/0 and the VPN halves, lowest metric first:
 * [{ gateway (IPv4 or null when "On-link"), ifaceIp, metric, split }].
 */
export function parseRoutePrintWin(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    // Active rows: destination, mask, gateway, interface address, metric. The gateway can be a
    // translated word of more than one token ("On-link", "Auf Verbindung"). Persistent rows have
    // no interface column, so they fail the five-column test.
    const f = line.trim().split(/\s+/);
    if (f.length < 5) continue;
    const [dest, mask] = f;
    const ifaceIp = f[f.length - 2];
    const metric = f[f.length - 1];
    const gw = f.slice(2, -2).join(" ");
    if (!net.isIPv4(dest) || !net.isIPv4(mask) || !net.isIPv4(ifaceIp) || !/^\d+$/.test(metric)) continue;
    const isDefault = dest === "0.0.0.0" && mask === "0.0.0.0";
    const isSplit = mask === "128.0.0.0" && (dest === "0.0.0.0" || dest === "128.0.0.0");
    if (!isDefault && !isSplit) continue;
    out.push({ gateway: net.isIPv4(gw) ? gw : null, ifaceIp, metric: Number(metric), split: isSplit });
  }
  return out.sort((a, b) => a.metric - b.metric);
}

// ---------- Wi-Fi -----------------------------------------------------------------------------

/** Frequency in MHz -> { band: "2.4"|"5"|"6", channel }. */
export function freqToChannel(mhz) {
  const f = Number(mhz);
  if (!Number.isFinite(f)) return { band: null, channel: null };
  if (f === 2484) return { band: "2.4", channel: 14 };
  if (f >= 2412 && f < 2484) return { band: "2.4", channel: Math.round((f - 2407) / 5) };
  if (f >= 5150 && f <= 5895) return { band: "5", channel: Math.round((f - 5000) / 5) };
  if (f >= 5925 && f <= 7125) return { band: "6", channel: Math.round((f - 5950) / 5) };
  return { band: null, channel: null };
}

/** Signal quality in percent (Windows, NetworkManager) -> approximate dBm. Both map -100..-50 dBm onto 0..100%. */
export const percentToDbm = (pct) => (pct === null || pct === undefined ? null : Math.round(pct / 2 - 100));

const macBand = (s) => {
  const m = /\((2|5|6)\s*GHz(?:,\s*(\d+)\s*MHz)?\)/i.exec(String(s));
  return m ? { band: m[1] === "2" ? "2.4" : m[1], width: m[2] ? Number(m[2]) : null } : { band: null, width: null };
};

/**
 * macOS `system_profiler -json SPAirPortDataType`. Network names are never read.
 * Returns { present, connected, iface, signal, noise, band, channel, width, phy, rate, neighbors }.
 */
export function parseMacAirport(jsonText) {
  let data;
  try {
    data = JSON.parse(jsonText);
  } catch {
    return { present: false, error: "unreadable" };
  }
  const ifaces = data?.SPAirPortDataType?.[0]?.spairport_airport_interfaces || [];
  const card = ifaces.find((i) => i.spairport_current_network_information || i.spairport_status_information) || ifaces[0];
  if (!card) return { present: false };
  const cur = card.spairport_current_network_information;
  const connected = card.spairport_status_information === "spairport_status_connected" && cur && cur.spairport_network_channel;
  const neighbors = (card.spairport_airport_other_local_wireless_networks || []).map((n) => {
    const ch = String(n.spairport_network_channel || "");
    const sn = /(-?\d+)\s*dBm/.exec(String(n.spairport_signal_noise || ""));
    return { channel: Number.parseInt(ch, 10) || null, band: macBand(ch).band, signal: sn ? Number(sn[1]) : null };
  });
  if (!connected) return { present: true, connected: false, iface: card._name || null, neighbors };
  const ch = String(cur.spairport_network_channel);
  const sn = /(-?\d+)\s*dBm\s*\/\s*(-?\d+)\s*dBm/.exec(String(cur.spairport_signal_noise || ""));
  const { band, width } = macBand(ch);
  return {
    present: true,
    connected: true,
    iface: card._name || null,
    signal: sn ? Number(sn[1]) : null,
    noise: sn ? Number(sn[2]) : null,
    band,
    channel: Number.parseInt(ch, 10) || null,
    width,
    phy: cur.spairport_network_phymode || null,
    rate: num(cur.spairport_network_rate),
    neighbors,
  };
}

/**
 * Windows `netsh wlan show interfaces`. Labels are read in English; the signal percentage, radio
 * type, channel and rates also fall back to value shapes, so a translated Windows still mostly works.
 * Returns { present, connected, name, signalPct, signal, band, channel, phy, rate } or { present, error }.
 */
export function parseNetshWlan(text) {
  const t = String(text);
  if (/location permission|ms-settings:privacy-location/i.test(t)) return { present: true, error: "location" };
  if (/wlansvc|Wireless AutoConfig Service/i.test(t)) return { present: false };
  if (/There is no wireless interface|no wireless interface on the system/i.test(t)) return { present: false };
  const rows = [];
  for (const line of t.split(/\r?\n/)) {
    const m = /^\s{2,}([^:]+?)\s*:\s(.*)$/.exec(line);
    if (m) rows.push([m[1].trim(), m[2].trim()]);
  }
  if (!rows.length) return { present: false };
  const get = (re) => rows.find(([k]) => re.test(k))?.[1] ?? null;
  const name = get(/^Name$/i);
  const state = get(/^State$/i);
  const signalRaw = get(/^Signal$/i) ?? rows.find(([, v]) => /^\d{1,3}\s*%$/.test(v))?.[1] ?? null;
  const signalPct = signalRaw ? num(signalRaw.replace("%", "")) : null;
  const rssi = num(get(/^Rssi$/i));
  const phy = get(/^Radio type$/i) ?? rows.find(([, v]) => /^802\.11\w+$/.test(v))?.[1] ?? null;
  const channel = num(get(/^Channel$|^Kanal$|^Canal$/i));
  const bandRaw = get(/^Band$/i);
  const rx = num(get(/^Receive rate/i));
  const tx = num(get(/^Transmit rate/i));
  let band = bandRaw ? (/2[.,]4/.test(bandRaw) ? "2.4" : /^5/.test(bandRaw) ? "5" : /^6/.test(bandRaw) ? "6" : null) : null;
  if (!band && channel) band = channel <= 14 ? "2.4" : null; // 5 and 6 GHz share channel numbers
  const connected = state ? /^connected$/i.test(state) : signalPct !== null;
  return {
    present: true,
    connected,
    name,
    signalPct,
    signal: rssi ?? percentToDbm(signalPct),
    signalEstimated: rssi === null,
    band,
    channel,
    phy,
    rate: rx ?? tx,
  };
}

/**
 * Names of the Wi-Fi adapters, from PowerShell's adapter list (one name per line). Windows hands this
 * out without location access, unlike the Wi-Fi details themselves.
 */
export function parseWifiAdapters(text) {
  return String(text)
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Windows `netsh wlan show networks mode=bssid` -> channels of nearby access points. */
export function parseNetshNetworks(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    const m = /^\s+(?:Channel|Kanal|Canal)\s*:\s*(\d+)/i.exec(line);
    if (m) out.push({ channel: Number(m[1]), band: Number(m[1]) <= 14 ? "2.4" : null, signal: null });
  }
  return out;
}

/** NetworkManager `nmcli -t -f IN-USE,CHAN,FREQ,RATE,SIGNAL,DEVICE dev wifi list`. */
export function parseNmcli(text) {
  const rows = [];
  for (const line of String(text).split("\n")) {
    if (!line.trim()) continue;
    const f = line.split(/(?<!\\):/);
    if (f.length < 6) continue;
    const [inUse, chan, freq, rate, signal, device] = f;
    const { band } = freqToChannel(Number.parseInt(freq, 10));
    rows.push({
      inUse: inUse.trim() === "*",
      channel: Number(chan) || null,
      band,
      rate: Number.parseInt(rate, 10) || null,
      signalPct: Number(signal),
      device: device.trim(),
    });
  }
  return rows;
}

/** `iw dev <if> link` -> { connected, freq, signal, rate }. */
export function parseIwLink(text) {
  const t = String(text);
  if (/Not connected/i.test(t) || !/Connected to/i.test(t)) return { connected: false };
  const freq = num(/freq:\s*([\d.]+)/.exec(t)?.[1]);
  const signal = num(/signal:\s*(-?\d+)\s*dBm/.exec(t)?.[1]);
  const rx = num(/rx bitrate:\s*([\d.]+)/.exec(t)?.[1]);
  const tx = num(/tx bitrate:\s*([\d.]+)/.exec(t)?.[1]);
  return { connected: true, freq: freq !== null ? Math.round(freq) : null, signal, rate: rx ?? tx };
}

/** Linux /proc/net/wireless -> [{ iface, signal (dBm) }]. */
export function parseProcWireless(text) {
  const out = [];
  for (const line of String(text).split("\n").slice(2)) {
    const m = /^\s*([^:\s]+):\s+\S+\s+[\d.]+\s+(-?[\d.]+)/.exec(line);
    if (!m) continue;
    let level = Number(m[2]);
    if (level > 0 && level <= 255) level -= 256; // some drivers report an unsigned byte
    out.push({ iface: m[1], signal: Math.round(level) });
  }
  return out;
}
