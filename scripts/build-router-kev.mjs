#!/usr/bin/env node
// Builds src/data/router-kev.json: the entries of CISA's Known Exploited Vulnerabilities catalog
// (https://www.cisa.gov/known-exploited-vulnerabilities-catalog, US government, public domain)
// that concern home and small-office routers, each with the model numbers named in it.
//
// Run before each release:  node scripts/build-router-kev.mjs [path-to-downloaded-catalog.json]
// The shipped tool never downloads anything; it only reads the file this script writes.
import fs from "node:fs";

const FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const OUT = new URL("../src/data/router-kev.json", import.meta.url);

// Makers of routers people have at home or in a small office. Cisco is limited to its
// small-business routers; the rest of its catalog entries are enterprise gear.
const MAKERS = {
  "D-Link": ["D-LINK", "DLINK"],
  "TP-Link": ["TP-LINK", "TPLINK"],
  NETGEAR: ["NETGEAR"],
  Linksys: ["LINKSYS"],
  ASUS: ["ASUS", "ASUSTEK"],
  Zyxel: ["ZYXEL"],
  Tenda: ["TENDA"],
  DrayTek: ["DRAYTEK"],
  Netis: ["NETIS"],
  Ubiquiti: ["UBIQUITI", "UBNT"],
  MikroTik: ["MIKROTIK"],
  Edimax: ["EDIMAX"],
  TOTOLINK: ["TOTOLINK"],
  Belkin: ["BELKIN"],
  Arris: ["ARRIS"],
  Huawei: ["HUAWEI"],
  ZTE: ["ZTE"],
  Cisco: ["CISCO"],
};

const CISCO_HOME = /\bRV\d{3}|Small Business.*Router/i;

// Model numbers look like TL-WR841N, DIR-859, RT-AX55, WNR2000v5, DGN2200, Archer AX21, AC15.
const MODEL = /\b(?:Archer\s+)?[A-Z]{1,5}(?:-[A-Z]{1,5})?-?\d{1,5}[A-Z]{0,4}\d{0,2}(?:\s?v\d{1,2})?\b/g;
// Things that match that shape but are not models.
const NOT_MODEL = /^(HTTP|HTTPS|TCP|UDP|SNMP|ACL|IP|IPV\d|DNS|SMB|NTP|AC\d{4}|AX\d{4}|N\d{3}|SSL\d?|TLS\d?|MD5|SHA\d+|V\d+|R\d)$|^(CVE|CWE)-?\d|^DHCP|^\d/i;

const norm = (s) => String(s).toUpperCase().replace(/[^A-Z0-9]/g, "");

function modelsIn(text) {
  const out = new Set();
  for (const m of String(text).matchAll(MODEL)) {
    const raw = m[0].replace(/\s?v\d{1,2}$/i, "");
    if (NOT_MODEL.test(raw.replace(/^Archer\s+/i, ""))) continue;
    const n = norm(raw);
    // Short ones only in the two-letters-and-a-number shape (Tenda AC7, AC10).
    if ((n.length >= 4 || /^[A-Z]{2}\d{1,2}$/.test(n)) && /[A-Z]/.test(n) && /\d/.test(n)) out.add(n);
  }
  return [...out];
}

const src = process.argv[2] ? fs.readFileSync(process.argv[2], "utf8") : await (await fetch(FEED)).text();
const catalog = JSON.parse(src);
const entries = [];
for (const v of catalog.vulnerabilities) {
  const maker = Object.keys(MAKERS).find((k) => norm(v.vendorProject) === norm(k));
  if (!maker) continue;
  if (maker === "Cisco" && !CISCO_HOME.test(`${v.product} ${v.vulnerabilityName}`)) continue;
  if (!/router|gateway|modem|wireless|wi-?fi|access point|extender|\bRV\d|DIR-|DSL|Archer|TL-|RT-|Nighthawk|Orbi|ZyWALL|USG|Vigor|EdgeRouter|RouterOS|AirOS/i.test(`${v.product} ${v.vulnerabilityName} ${v.shortDescription}`)) continue;
  const models = modelsIn(`${v.product} ${v.shortDescription}`);
  entries.push({
    maker,
    product: v.product,
    cve: v.cveID,
    added: v.dateAdded,
    ransomware: v.knownRansomwareCampaignUse === "Known",
    models,
  });
}
entries.sort((a, b) => a.maker.localeCompare(b.maker) || b.added.localeCompare(a.added));
const data = { source: "CISA Known Exploited Vulnerabilities catalog", catalogVersion: catalog.catalogVersion, makers: MAKERS, entries };
fs.writeFileSync(OUT, JSON.stringify(data, null, 1) + "\n");
console.log(`${entries.length} router entries (${entries.filter((e) => e.models.length).length} name a model), catalog ${catalog.catalogVersion}`);
