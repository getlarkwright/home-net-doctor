// The readers, fed recorded output. Linux and Mac files are real captures with addresses swapped
// for documentation ones (RFC 5737); the Windows files follow Microsoft's documented formats,
// including a German system, and CI checks the readers against real Windows output as well.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import {
  parsePing,
  parseProcRoute,
  parseNetstatDarwin,
  parseRoutePrintWin,
  parseMacAirport,
  parseNetshWlan,
  parseNetshNetworks,
  parseNmcli,
  parseIwLink,
  parseProcWireless,
  freqToChannel,
  percentToDbm,
  parseWifiAdapters,
} from "../src/lib/parse.js";

const fx = (name) => fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");

test("ping: Linux, all answered", () => {
  const p = parsePing(fx("linux-ping.txt"));
  assert.equal(p.received, 3);
  assert.deepEqual(p.times, [0.356, 0.304, 0.394]);
});

test("ping: Linux, losses, a duplicate and an unreachable line are not replies", () => {
  const p = parsePing(fx("linux-ping-loss.txt"));
  assert.equal(p.received, 3);
  assert.deepEqual(p.times, [3.1, 187, 12.4]);
});

test("ping: macOS real output", () => {
  assert.deepEqual(parsePing(fx("mac-ping.txt")).times, [4.021, 2.952, 6.695, 3.382]);
  assert.equal(parsePing(fx("mac-ping-lost.txt")).received, 0);
});

test("ping: Windows English, including time<1ms and host unreachable", () => {
  const p = parsePing(fx("win-ping-en.txt"));
  assert.equal(p.received, 3, "the 'Destination host unreachable' reply has no TTL and must not count");
  assert.deepEqual(p.times, [2, 0.5, 41]);
});

test("ping: Windows German", () => {
  const p = parsePing(fx("win-ping-de.txt"));
  assert.equal(p.received, 2);
  assert.deepEqual(p.times, [3, 4]);
});

test("routes: Linux picks the lowest metric and reads little-endian gateways", () => {
  const r = parseProcRoute(fx("linux-proc-route.txt"));
  assert.equal(r.length, 2);
  assert.deepEqual(r[0], { iface: "enp6s18", gateway: "192.0.2.1", metric: 100, split: false });
  assert.equal(r[1].gateway, "198.51.100.1");
});

test("routes: Linux VPN using the two half routes", () => {
  const r = parseProcRoute(fx("linux-proc-route-vpn.txt"));
  assert.equal(r.filter((x) => x.split).length, 2);
  assert.equal(r.find((x) => x.split).iface, "tun0");
  assert.deepEqual(r.find((x) => !x.split), { iface: "wlp2s0", gateway: "192.0.2.1", metric: 600, split: false });
});

test("routes: macOS behind a VPN (real table)", () => {
  const r = parseNetstatDarwin(fx("mac-netstat.txt"));
  assert.equal(r.length, 3);
  assert.deepEqual(r[0], { gateway: null, flags: "UCSg", iface: "utun8", scoped: false, split: false });
  assert.deepEqual(r[1], { gateway: "192.0.2.1", flags: "UGScIg", iface: "en0", scoped: true, split: false });
});

test("routes: Windows English", () => {
  const r = parseRoutePrintWin(fx("win-route-print.txt"));
  assert.equal(r.length, 1, "persistent routes have no interface column and are skipped");
  assert.deepEqual(r[0], { gateway: "192.0.2.1", ifaceIp: "192.0.2.50", metric: 35, split: false });
});

test("routes: Windows German with an on-link VPN route first", () => {
  const r = parseRoutePrintWin(fx("win-route-print-de-vpn.txt"));
  assert.equal(r.length, 2);
  assert.deepEqual(r[0], { gateway: null, ifaceIp: "203.0.113.7", metric: 5, split: false });
  assert.equal(r[1].gateway, "192.0.2.1");
});

test("Wi-Fi: macOS real report (6 GHz, names never returned)", () => {
  const w = parseMacAirport(fx("mac-airport.json"));
  assert.equal(w.connected, true);
  assert.equal(w.iface, "en0");
  assert.equal(w.signal, -48);
  assert.equal(w.noise, -91);
  assert.equal(w.band, "6");
  assert.equal(w.channel, 37);
  assert.equal(w.width, 160);
  assert.equal(w.phy, "802.11ax");
  assert.equal(w.rate, 1361);
  assert.equal(w.neighbors.length, 25);
  assert.ok(w.neighbors.some((n) => n.band === "2.4" && n.channel === 11));
  assert.ok(!JSON.stringify(w).includes("Home Network") && !JSON.stringify(w).includes("Neighbor"));
});

test("Wi-Fi: macOS, Wi-Fi off or unreadable", () => {
  const off = JSON.stringify({ SPAirPortDataType: [{ spairport_airport_interfaces: [{ _name: "en0", spairport_status_information: "spairport_status_off" }] }] });
  assert.deepEqual(parseMacAirport(off), { present: true, connected: false, iface: "en0", neighbors: [] });
  assert.equal(parseMacAirport("not json").present, false);
});

test("Wi-Fi: Windows English", () => {
  const w = parseNetshWlan(fx("win-netsh-wlan.txt"));
  assert.equal(w.connected, true);
  assert.equal(w.name, "Wi-Fi");
  assert.equal(w.signalPct, 38);
  assert.equal(w.signal, -81);
  assert.equal(w.signalEstimated, true);
  assert.equal(w.band, "2.4");
  assert.equal(w.channel, 6);
  assert.equal(w.phy, "802.11n");
  assert.equal(w.rate, 72.2);
  assert.ok(!JSON.stringify(w).includes("Home Network"));
});

test("Wi-Fi: Windows location permission and no Wi-Fi service", () => {
  assert.deepEqual(parseNetshWlan(fx("win-netsh-location.txt")), { present: true, error: "location" });
  assert.deepEqual(parseNetshWlan(fx("win-netsh-nosvc.txt")), { present: false });
});

test("Wi-Fi: Windows adapter names from PowerShell", () => {
  assert.deepEqual(parseWifiAdapters("Wi-Fi\r\n\r\n"), ["Wi-Fi"]);
  assert.deepEqual(parseWifiAdapters(""), []);
});

test("Wi-Fi: Windows nearby networks", () => {
  const n = parseNetshNetworks(fx("win-netsh-networks.txt"));
  assert.deepEqual(n.map((x) => x.channel), [6, 4, 149]);
});

test("Wi-Fi: Linux nmcli, iw and /proc/net/wireless", () => {
  const rows = parseNmcli(fx("linux-nmcli.txt"));
  assert.equal(rows.length, 4);
  assert.deepEqual(rows[0], { inUse: true, channel: 44, band: "5", rate: 540, signalPct: 78, device: "wlp2s0" });
  assert.equal(rows[1].inUse, false);
  assert.deepEqual(parseIwLink(fx("linux-iw-link.txt")), { connected: true, freq: 5180, signal: -71, rate: 433.3 });
  assert.deepEqual(parseIwLink("Not connected."), { connected: false });
  assert.deepEqual(parseProcWireless(fx("linux-proc-wireless.txt")), [{ iface: "wlp2s0", signal: -66 }]);
});

test("frequency and percentage helpers", () => {
  assert.deepEqual(freqToChannel(2437), { band: "2.4", channel: 6 });
  assert.deepEqual(freqToChannel(2484), { band: "2.4", channel: 14 });
  assert.deepEqual(freqToChannel(5180), { band: "5", channel: 36 });
  assert.deepEqual(freqToChannel(6135), { band: "6", channel: 37 });
  assert.equal(percentToDbm(100), -50);
  assert.equal(percentToDbm(0), -100);
});
