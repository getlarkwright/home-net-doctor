import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import dgram from "node:dgram";
import http from "node:http";

import { parseSsdp, parseDescription, parseArp, ouiVendor, hasModel, matchKev, checkRouter, renderRouter } from "../src/lib/router.js";

const fx = (name) => fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");

test("UPnP reply and description", () => {
  const r = parseSsdp(fx("ssdp-reply.txt"));
  assert.equal(r.location, "http://192.0.2.1:5000/rootDesc.xml");
  assert.match(r.st, /InternetGatewayDevice/);
  const d = parseDescription(fx("upnp-igd.xml"));
  assert.equal(d.manufacturer, "TP-Link");
  assert.equal(d.modelName, "Archer AX21");
  assert.equal(d.portMapping, true);
});

test("address tables on Linux, macOS (short octets) and Windows", () => {
  assert.equal(parseArp(fx("linux-proc-arp.txt"), "192.0.2.1"), "50:c7:bf:12:34:56");
  assert.equal(parseArp(fx("linux-proc-arp.txt"), "192.0.2.7"), null, "an incomplete entry is not an address");
  assert.equal(parseArp(fx("mac-arp.txt"), "192.0.2.1"), "50:c7:bf:02:03:04");
  assert.equal(parseArp(fx("win-arp.txt"), "192.0.2.1"), "50:c7:bf:12:34:56");
  assert.equal(parseArp(fx("win-arp.txt"), "192.0.2.10"), null, "192.0.2.10 must not match 192.0.2.1");
});

test("maker from the hardware address, and randomized addresses", () => {
  assert.match(ouiVendor("50:c7:bf:12:34:56").vendor, /TP-LINK/);
  assert.deepEqual(ouiVendor("02:00:00:00:00:01"), { vendor: null, randomized: true });
  assert.deepEqual(ouiVendor(null), { vendor: null });
});

test("model numbers match whole models only", () => {
  assert.ok(hasModel("Archer AX21", "ARCHERAX21"));
  assert.ok(hasModel("TL-WR841N v14", "TLWR841N"));
  assert.ok(hasModel("Tenda AC7", "AC7"));
  assert.ok(!hasModel("AC750", "AC7"), "AC750 is a different router");
  assert.ok(!hasModel("Archer AX210", "ARCHERAX21"));
  assert.ok(hasModel("DIR-820L", "DIR820"));
});

test("the CISA list is matched by maker and model", () => {
  const hits = matchKev({ manufacturer: "TP-Link", modelName: "Archer AX21" });
  assert.deepEqual(hits.map((h) => h.cve), ["CVE-2023-1389"]);
  assert.equal(matchKev({ manufacturer: "NETGEAR", modelName: "Archer AX21" }).length, 0, "the maker must match too");
  assert.equal(matchKev({ manufacturer: "NETGEAR", modelName: "Nighthawk R7000" }).length, 0);
  // The maker can come from the hardware address when the description leaves it out.
  assert.equal(matchKev({ vendor: "TP-LINK TECHNOLOGIES CO.,LTD.", modelName: "TL-WR841N" }).length >= 1, true);
  assert.equal(matchKev({}).length, 0);
});

test("end to end against a pretend router on this computer", async () => {
  const xml = fx("upnp-igd.xml");
  const web = http.createServer((req, res) => {
    res.writeHead(req.url === "/rootDesc.xml" ? 200 : 404, { "content-type": "text/xml" });
    res.end(req.url === "/rootDesc.xml" ? xml : "");
  });
  await new Promise((r) => web.listen(0, "127.0.0.1", r));
  const ssdp = dgram.createSocket("udp4");
  await new Promise((r) => ssdp.bind(0, "127.0.0.1", r));
  ssdp.on("message", (msg, rinfo) => {
    if (!/M-SEARCH/.test(msg) || !/InternetGatewayDevice:1/.test(msg)) return;
    const reply = `HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:${web.address().port}/rootDesc.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:1\r\n\r\n`;
    ssdp.send(reply, rinfo.port, rinfo.address);
  });
  try {
    const r = await checkRouter({ routerIp: "127.0.0.1", ssdpPort: ssdp.address().port, skipMac: true });
    assert.equal(r.found, true);
    assert.equal(r.upnpOn, true);
    assert.equal(r.description.modelName, "Archer AX21");
    assert.deepEqual(r.matches.map((m) => m.cve), ["CVE-2023-1389"]);
    const text = renderRouter(r);
    assert.match(text, /Router: TP-Link Archer AX21 \(from the router's own announcement/);
    assert.match(text, /\[warning\] This model may have security holes/);
    assert.match(text, /CVE-2023-1389: TP-Link Archer AX21, listed 2023-05-01/);
    assert.match(text, /UPnP appears to be on/);
    assert.match(text, /nothing logged into the router/);
  } finally {
    ssdp.close();
    web.close();
  }
});

test("a description from any address other than the router is never fetched", async () => {
  const { fetchDescription } = await import("../src/lib/router.js");
  assert.equal(await fetchDescription("http://198.51.100.9/rootDesc.xml", "192.0.2.1"), null);
  assert.equal(await fetchDescription("https://192.0.2.1/rootDesc.xml", "192.0.2.1"), null);
});

test("report when nothing is known about the router", () => {
  const text = renderRouter({ found: true, answeredUpnp: false, upnpOn: false, description: null, vendor: null, randomizedMac: true, matches: [], listVersion: "2026.11.23" });
  assert.match(text, /randomized hardware address/);
  assert.match(text, /Find the model on the router's label, look it up on the maker's support site/);
  assert.match(renderRouter({ found: false, viaVpn: true }), /VPN/);
});
