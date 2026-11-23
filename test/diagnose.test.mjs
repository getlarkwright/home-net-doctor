// The verdict rules, fed made-up facts: one healthy home, then one thing broken at a time.
import { test } from "node:test";
import assert from "node:assert/strict";

import { diagnose, rateSignal, crowding } from "../src/lib/diagnose.js";
import { renderConnection, renderWifi } from "../src/lib/report.js";
import { stats } from "../src/lib/gather.js";

const probe = (times, sent = 10, extra = {}) => ({ method: "ping", target: "192.0.2.1", ...stats(times, sent), ...extra });
const steady = (ms, n = 10) => Array.from({ length: n }, () => ms);

function healthy(over = {}) {
  const base = {
    platform: "linux",
    seconds: 11,
    interfaces: { list: [], hasAny: true, selfAssignedOnly: false, hasGlobalV6: false, tunnels: [] },
    routes: { primaryIface: "wlan0", viaVpn: false, router: { ip: "192.0.2.1", iface: "wlan0" }, vpnIfaces: [], error: null },
    router: probe(steady(3)),
    internet: {
      best: { ...probe(steady(15)), target: "1.1.1.1", label: "Cloudflare" },
      all: [{ ...probe(steady(15)), target: "1.1.1.1", label: "Cloudflare" }, { ...probe(steady(18)), target: "8.8.8.8", label: "Google" }],
    },
    dns: {
      system: { works: true, ms: 20 },
      servers: [
        { server: "192.0.2.1", label: "your DNS server", kind: "yours", works: true, ms: 25, madeUp: false },
        { server: "1.1.1.1", label: "Cloudflare DNS", kind: "public", works: true, ms: 15, madeUp: false },
        { server: "8.8.8.8", label: "Google DNS", kind: "public", works: true, ms: 20, madeUp: false },
      ],
    },
    captive: { state: "clear", clockSkewSec: 1 },
    https: { works: true, ms: 40 },
    ipv6: { has: false },
    wifi: { present: true, connected: true, iface: "wlan0", signal: -55, noise: -92, band: "5", channel: 44, rate: 600, neighbors: [] },
    onWifi: true,
  };
  return { ...base, ...over };
}

const code = (f) => diagnose(f).verdict.code;

test("a healthy home says so, with no problems or warnings", () => {
  const d = diagnose(healthy());
  assert.equal(d.verdict.code, "healthy");
  assert.ok(!d.findings.some((x) => x.level === "problem" || x.level === "warning"));
});

test("not connected, and connected without an address", () => {
  assert.equal(code(healthy({ interfaces: { list: [], hasAny: false, selfAssignedOnly: false, tunnels: [] } })), "no_network");
  assert.equal(code(healthy({ interfaces: { list: [], hasAny: false, selfAssignedOnly: true, tunnels: [] } })), "no_address");
});

test("a sign-in page wins over everything after the basics", () => {
  assert.equal(code(healthy({ captive: { state: "portal", status: 302, host: "login.example.net" } })), "portal");
  // A non-redirect answer is only a note (a filter), not a sign-in page.
  assert.equal(code(healthy({ captive: { state: "portal", status: 200 } })), "healthy");
});

test("router unreachable and nothing gets out", () => {
  const f = healthy({
    router: probe([]),
    internet: { best: { ...probe([]), label: "Cloudflare" }, all: [{ ...probe([]), label: "Cloudflare" }] },
    https: { works: false, error: "timeout" },
  });
  const d = diagnose(f);
  assert.equal(d.verdict.code, "router_unreachable");
  assert.match(d.steps.join(" "), /own home network/);
});

test("Wi-Fi losses to the router are blamed on the Wi-Fi, with 5 GHz advice on 2.4 GHz", () => {
  const f = healthy({
    router: probe([3, 4, 250, 5, 180, 6, 7], 10),
    wifi: { present: true, connected: true, iface: "wlan0", signal: -79, band: "2.4", channel: 6, rate: 54, neighbors: [] },
  });
  const d = diagnose(f);
  assert.equal(d.verdict.code, "wifi");
  assert.match(d.steps.join(" "), /5 GHz/);
  assert.ok(d.findings.some((x) => x.area === "wifi" && x.level === "warning" && /weak/.test(x.text)));
});

test("internet losses that come from the Wi-Fi leg are not called a second problem", () => {
  const lossy = { ...probe([22, 25, 240, 24, 31, 410, 23, 26], 10), target: "1.1.1.1", label: "Cloudflare" };
  const d = diagnose(healthy({ router: probe([4, 6, 212, 9, 5, 388, 7, 11], 10), internet: { best: lossy, all: [lossy] } }));
  assert.equal(d.verdict.code, "wifi");
  const inet = d.findings.find((x) => x.area === "internet");
  assert.equal(inet.level, "warning");
  assert.match(inet.text, /comes from the leg to your router/);
  // But a much worse internet leg is still its own problem.
  const awful = { ...probe([400, 410, 420], 10), target: "1.1.1.1", label: "Cloudflare" };
  const d2 = diagnose(healthy({ router: probe(steady(3, 9), 10), internet: { best: awful, all: [awful] } }));
  assert.equal(d2.findings.find((x) => x.area === "internet").level, "problem");
});

test("a slow router leg with a strong signal does not say 'move closer' (real Mac run on a phone hotspot)", () => {
  const router = probe([3.8, 45, 99.6, 20, 60, 30, 70, 41, 52, 30]);
  const inet = { ...probe([47, 120, 204.7, 90, 110, 130, 100, 80, 120, 118]), target: "8.8.8.8", label: "Google" };
  const d = diagnose(healthy({ router, internet: { best: inet, all: [inet] }, wifi: { ...healthy().wifi, signal: -35, channel: 149 } }));
  assert.equal(d.verdict.code, "warning_router");
  assert.match(d.verdict.title, /even though the Wi-Fi signal is strong/);
  assert.ok(!d.steps.some((s) => /Move closer/.test(s)));
  assert.ok(d.steps.some((s) => /hotspot/.test(s)));
  // The internet leg adds about 55 ms of its own, so it is not blamed on the router leg.
  assert.match(d.findings.find((x) => x.area === "internet").text, /Typical home internet/);
});

test("the same losses on a cable point at the cable", () => {
  const f = healthy({ router: probe([1, 1, 1, 1, 1, 1], 10), onWifi: false });
  assert.equal(code(f), "local_link");
  assert.match(diagnose(f).steps[0], /cable/);
});

test("router fine but nothing past it: internet down; through a VPN: VPN down", () => {
  const dead = { internet: { best: { ...probe([]), label: "Cloudflare" }, all: [{ ...probe([]), label: "Cloudflare" }] }, https: { works: false, error: "timeout" } };
  assert.equal(code(healthy(dead)), "internet_down");
  assert.equal(code(healthy({ ...dead, routes: { ...healthy().routes, viaVpn: true, vpnIfaces: ["wg0"] } })), "vpn_down");
});

test("router fine, internet lossy or very slow: the internet company", () => {
  const lossy = { ...probe([20, 22, 21, 300, 25, 24, 23], 10), label: "Cloudflare" };
  const d = diagnose(healthy({ internet: { best: lossy, all: [lossy] } }));
  assert.equal(d.verdict.code, "isp");
  assert.match(d.steps.join(" "), /modem/);
  const slow = { ...probe(steady(400)), label: "Cloudflare" };
  assert.equal(code(healthy({ internet: { best: slow, all: [slow] } })), "isp");
});

test("a router that ignores pings is not mistaken for broken Wi-Fi", () => {
  const d = diagnose(healthy({ router: probe([]) }));
  assert.equal(d.verdict.code, "healthy");
  assert.ok(d.findings.some((x) => x.area === "router" && x.level === "note"));
});

test("DNS failing while public DNS works", () => {
  const f = healthy({
    dns: {
      system: { works: false, error: "ENOTFOUND" },
      servers: [
        { server: "192.0.2.1", label: "your DNS server", kind: "yours", works: false, error: "ETIMEOUT" },
        { server: "1.1.1.1", label: "Cloudflare DNS", kind: "public", works: true, ms: 15 },
      ],
    },
  });
  const d = diagnose(f);
  assert.equal(d.verdict.code, "dns");
  assert.match(d.steps.join(" "), /public DNS/);
});

test("slow DNS and made-up answers are a warning and a note", () => {
  const f = healthy({
    dns: {
      system: { works: true, ms: 900 },
      servers: [
        { server: "192.0.2.1", label: "your DNS server", kind: "yours", works: true, ms: 800, madeUp: true },
        { server: "1.1.1.1", label: "Cloudflare DNS", kind: "public", works: true, ms: 20 },
      ],
    },
  });
  const d = diagnose(f);
  assert.equal(d.verdict.code, "warning_dns");
  assert.ok(d.findings.some((x) => x.level === "note" && /makes up answers/.test(x.text)));
});

test("secure connections: blocked, wrong clock, inspected", () => {
  assert.equal(code(healthy({ https: { works: false, error: "ECONNRESET" } })), "https_blocked");
  assert.equal(code(healthy({ https: { works: false, error: "CERT_NOT_YET_VALID", clock: true } })), "clock");
  assert.equal(code(healthy({ https: { works: false, error: "SELF_SIGNED_CERT_IN_CHAIN", inspected: true } })), "healthy");
});

test("broken IPv6, a skewed clock and a VPN are reported", () => {
  assert.equal(code(healthy({ ipv6: { has: true, works: false, error: "timeout" } })), "warning_ipv6");
  assert.equal(code(healthy({ captive: { state: "clear", clockSkewSec: -900 } })), "warning_clock");
  const d = diagnose(healthy({ routes: { ...healthy().routes, viaVpn: true, vpnIfaces: ["utun8"] } }));
  assert.equal(d.verdict.code, "healthy");
  assert.ok(d.findings.some((x) => x.area === "vpn" && /utun8/.test(x.text)));
  assert.match(d.steps[0], /VPN/);
});

test("signal rating and channel crowding", () => {
  assert.equal(rateSignal(-48).word, "strong");
  assert.equal(rateSignal(-70).word, "fair");
  assert.equal(rateSignal(-80).word, "weak");
  assert.equal(rateSignal(-90).word, "very weak");
  assert.equal(rateSignal(null), null);
  const w = { band: "2.4", channel: 6, neighbors: [{ channel: 1 }, { channel: 4 }, { channel: 6 }, { channel: 9 }, { channel: 11 }, { channel: 44 }] };
  assert.equal(crowding(w), 3);
  assert.equal(crowding({ band: "5", channel: 44, neighbors: [{ channel: 44, band: "5" }, { channel: 48, band: "5" }, { channel: 44, band: null }] }), 2);
});

test("the report never contains a network name and reads in plain words", () => {
  const text = renderConnection(healthy({ wifi: { ...healthy().wifi, name: "Home Network" } }));
  assert.match(text, /^Home Net Doctor: connection check \(Linux, on Wi-Fi; took 11 s\)/);
  assert.match(text, /Verdict: Everything looks healthy/);
  assert.match(text, /Measurements/);
  assert.ok(!text.includes("Home Network"));
  const wifiText = renderWifi({ present: true, connected: true, signal: -72, noise: -90, band: "2.4", channel: 6, phy: "802.11n", rate: 72, neighbors: [] });
  assert.match(wifiText, /Signal: fair/);
  assert.match(wifiText, /Wi-Fi 4, older/);
  assert.match(renderWifi({ present: true, connected: null, note: "Windows hides Wi-Fi details until location access is on" }), /location access/);
});
