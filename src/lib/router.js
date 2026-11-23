// check_router: who made the home router, which model it says it is, whether UPnP is on, and
// whether that model is on CISA's list of router security holes that criminals are using.
//
// Everything stays inside the home network: one UPnP search (sent straight to the router and to
// the standard UPnP group address), one read of the router's public UPnP description, and this
// computer's own address table. It never logs into the router and never tries a password.
import dgram from "node:dgram";
import fs from "node:fs";
import zlib from "node:zlib";
import http from "node:http";
import net from "node:net";

import { run } from "./run.js";
import { getInterfaces, getRoutes, tcpConnect } from "./gather.js";

/** The standard UPnP group address (SSDP). Not a host: every UPnP device on the network listens on it. */
export const SSDP_GROUP = "239.255.255.250";

const KEV = JSON.parse(fs.readFileSync(new URL("../data/router-kev.json", import.meta.url), "utf8"));

const SEARCH_TARGETS = ["urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2", "upnp:rootdevice"];

// ---------- readers ---------------------------------------------------------------------------

/** One SSDP reply ("HTTP/1.1 200 OK" plus headers) -> { location, st, usn, server } with lower-case keys. */
export function parseSsdp(text) {
  const out = {};
  for (const line of String(text).split(/\r?\n/).slice(1)) {
    const m = /^([^:]+):\s*(.*)$/.exec(line);
    if (m) out[m[1].trim().toLowerCase()] = m[2].trim();
  }
  return out;
}

const tag = (xml, name) => {
  const m = new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`, "i").exec(xml);
  return m ? m[1].replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").trim() || null : null;
};

/** A UPnP device description -> the top device's maker and model, and whether it offers port mapping. */
export function parseDescription(xml) {
  const s = String(xml);
  const device = s.slice(s.search(/<device>/i) >= 0 ? s.search(/<device>/i) : 0);
  return {
    manufacturer: tag(device, "manufacturer"),
    modelName: tag(device, "modelName"),
    modelNumber: tag(device, "modelNumber"),
    modelDescription: tag(device, "modelDescription"),
    friendlyName: tag(device, "friendlyName"),
    portMapping: /WAN(IP|PPP)Connection/i.test(s),
  };
}

const fixMac = (m) =>
  String(m)
    .split(/[:-]/)
    .map((x) => x.padStart(2, "0"))
    .join(":")
    .toLowerCase();

/** The router's hardware address from this computer's address (ARP) table, in any of the three formats. */
export function parseArp(text, ip) {
  for (const line of String(text).split(/\r?\n/)) {
    if (!new RegExp(`(^|[\\s(])${ip.replace(/\./g, "\\.")}([\\s)]|$)`).test(line)) continue;
    const m = /\b([0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){5})\b/i.exec(line);
    if (m && !/^(0{1,2}[:-]){5}0{1,2}$/.test(m[1])) return fixMac(m[1]);
  }
  return null;
}

let OUI = null;
/** Maker of a network card from the IEEE registry (bundled), or why it can't be told. */
export function ouiVendor(mac) {
  if (!mac) return { vendor: null };
  const hex = mac.replace(/[^0-9a-f]/gi, "").toUpperCase();
  if (parseInt(hex.slice(0, 2), 16) & 0x02) return { vendor: null, randomized: true };
  if (!OUI) {
    OUI = new Map();
    const tsv = zlib.gunzipSync(fs.readFileSync(new URL("../data/oui.tsv.gz", import.meta.url))).toString("utf8");
    for (const line of tsv.split("\n")) if (line.charCodeAt(6) === 9) OUI.set(line.slice(0, 6), line.slice(7).trim());
  }
  return { vendor: OUI.get(hex.slice(0, 6)) || null };
}

// ---------- matching ----------------------------------------------------------------------------

const norm = (s) => String(s || "").toUpperCase().replace(/[^A-Z0-9]/g, "");

/** Does the text contain this model number as a whole model (separators ignored, no extra digits after it)? */
export function hasModel(text, token) {
  const body = token.split("").map((c) => c.replace(/[^A-Z0-9]/g, "")).join("[\\s_-]*");
  return new RegExp(`(^|[^A-Z0-9])${body}(?![0-9])`).test(String(text || "").toUpperCase());
}

/** Entries of the bundled CISA list that name this router's maker and model. */
export function matchKev(identity, data = KEV) {
  const makerText = norm(`${identity.manufacturer || ""} ${identity.vendor || ""}`);
  const modelText = [identity.modelName, identity.modelNumber, identity.modelDescription, identity.friendlyName].filter(Boolean).join(" | ");
  if (!makerText || !modelText) return [];
  return data.entries.filter((e) => {
    const aliases = data.makers[e.maker] || [e.maker];
    if (!aliases.some((a) => makerText.includes(norm(a)))) return false;
    return e.models.some((m) => hasModel(modelText, m));
  });
}

// ---------- gathering -----------------------------------------------------------------------------

/**
 * Asks for the router's UPnP announcement, both straight at the router (as UPnP 1.1 allows) and
 * through the standard group address that older routers only answer on. Only replies from the
 * router's own address are kept.
 */
export function ssdpSearch(routerIp, { port = 1900, group = SSDP_GROUP, localIp = null, timeoutMs = 2500 } = {}) {
  return new Promise((resolve) => {
    const replies = [];
    const sock = dgram.createSocket({ type: "udp4", reuseAddr: true });
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      try {
        sock.close();
      } catch {
        /* already closed */
      }
      resolve(replies);
    };
    sock.on("error", finish);
    sock.on("message", (buf, rinfo) => {
      if (rinfo.address !== routerIp) return; // a reply from anyone else is ignored
      replies.push(parseSsdp(buf.toString("utf8", 0, Math.min(buf.length, 4096))));
    });
    sock.bind(0, () => {
      try {
        // Send the group search out of the interface that faces the router, not a VPN.
        if (group && localIp) sock.setMulticastInterface(localIp);
      } catch {
        /* the default interface will do */
      }
      const search = (host, st) => Buffer.from(`M-SEARCH * HTTP/1.1\r\nHOST: ${host}:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ${st}\r\n\r\n`);
      for (const st of SEARCH_TARGETS) {
        sock.send(search(routerIp, st), port, routerIp, () => {});
        if (group) sock.send(search(group, st), port, group, () => {});
      }
      setTimeout(finish, timeoutMs).unref?.();
    });
  });
}

/** Reads the router's UPnP description, only from the router's own address, capped at 256 KB. */
export function fetchDescription(location, routerIp) {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(location);
    } catch {
      return resolve(null);
    }
    if (u.protocol !== "http:" || u.hostname !== routerIp) return resolve(null);
    const req = http.get({ host: routerIp, port: u.port || 80, path: u.pathname + u.search, timeout: 3000, agent: false, headers: { "user-agent": "home-net-doctor" } }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return resolve(null);
      }
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (d) => {
        body += d;
        if (body.length > 256 * 1024) req.destroy();
      });
      res.on("end", () => resolve(body));
      res.on("close", () => resolve(body || null));
    });
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(null));
  });
}

async function routerMac(ip) {
  await tcpConnect(ip, 80, 1500); // make sure the address table has a fresh entry
  if (process.platform === "linux") {
    try {
      return parseArp(fs.readFileSync("/proc/net/arp", "utf8"), ip);
    } catch {
      return null;
    }
  }
  const r = await run("arp", process.platform === "win32" ? ["-a", ip] : ["-n", ip], { timeoutMs: 8000 });
  return parseArp(r.stdout, ip);
}

export async function checkRouter(opts = {}) {
  let routerIp = opts.routerIp;
  let iface = null;
  const interfaces = getInterfaces();
  if (!routerIp) {
    const routes = await getRoutes(interfaces);
    routerIp = routes.router?.ip;
    iface = routes.router?.iface;
    if (!routerIp) return { found: false, viaVpn: routes.viaVpn };
  }
  const localIp = interfaces.list.find((a) => a.name === iface && a.family === "IPv4")?.address || null;
  const [replies, mac] = await Promise.all([
    // A test passes its own port; then only the direct search is sent.
    ssdpSearch(routerIp, opts.ssdpPort ? { port: opts.ssdpPort, group: null } : { localIp }),
    opts.skipMac ? Promise.resolve(null) : routerMac(routerIp),
  ]);
  const igdReply = replies.find((r) => /InternetGatewayDevice/i.test(`${r.st} ${r.usn}`));
  const withLocation = igdReply?.location ? igdReply : replies.find((r) => r.location);
  const xml = withLocation ? await fetchDescription(withLocation.location, routerIp) : null;
  const desc = xml ? parseDescription(xml) : null;
  const oui = ouiVendor(mac);
  const identity = { ...(desc || {}), vendor: oui.vendor };
  return {
    found: true,
    routerIp,
    answeredUpnp: replies.length > 0,
    upnpOn: Boolean(igdReply || desc?.portMapping),
    description: desc,
    vendor: oui.vendor,
    randomizedMac: Boolean(oui.randomized),
    matches: matchKev(identity),
    listVersion: KEV.catalogVersion,
  };
}

// ---------- report ----------------------------------------------------------------------------

const cleanVendor = (v) =>
  v
    ? v
        .replace(/\b(TECHNOLOGIES|TECHNOLOGY|CO\.?,?\s*LTD\.?|INC\.?|CORPORATION|CORP\.?|LIMITED|LLC|GMBH|COMPUTER)\b/gi, "")
        .replace(/[,\s.]+$/g, "")
        .replace(/\s{2,}/g, " ")
        .trim()
    : null;

export function renderRouter(r) {
  const head = "Home Net Doctor: router check";
  if (!r.found) {
    return `${head}\n\n${r.viaVpn ? "All traffic goes through a VPN, so the home router is hidden from this computer. Turn the VPN off and run this again." : "I could not find a router: this computer has no way out to a home network right now."}`;
  }
  const d = r.description;
  const maker = d?.manufacturer || cleanVendor(r.vendor);
  // Some routers put a version ("1.0") in the model number; only a real model number is shown.
  const number = d?.modelNumber && /[A-Z]/i.test(d.modelNumber) && !/^v?[\d.]+$/i.test(d.modelNumber) && !String(d.modelName || "").includes(d.modelNumber) ? d.modelNumber : null;
  const model = [d?.modelName, number].filter(Boolean).join(" ");
  const lines = [head, ""];
  if (d && (maker || model)) {
    lines.push(`Router: ${[maker, model].filter(Boolean).join(" ") || "unnamed"} (from the router's own announcement on your network)`);
  } else if (maker) {
    lines.push(`Router: made by ${maker} (from its network maker code). It does not announce its model, so it can't be checked against the list of known problems. The model is printed on the label underneath.`);
  } else {
    lines.push(
      `Router: it does not say who made it or which model it is${r.randomizedMac ? " (it uses a private, randomized hardware address)" : ""}, so it can't be checked against the list of known problems. The model is printed on the label underneath.`,
    );
  }
  lines.push("", "What I found");
  const listDate = String(r.listVersion || "").replace(/\./g, "-");
  if (r.matches.length) {
    lines.push(
      `[warning] This model may have security holes that criminals are actively using: it matches ${r.matches.length === 1 ? "an entry" : `${r.matches.length} entries`} on CISA's Known Exploited Vulnerabilities list (the US government's list).`,
    );
    for (const m of r.matches) lines.push(`          ${m.cve}: ${m.maker} ${m.product}, listed ${m.added}${m.ransomware ? ", used in ransomware" : ""}`);
    lines.push("          A match by model can include hardware versions that were fixed or never affected; the maker's notice for each one says which.");
  } else if (d && model) {
    lines.push(`[ok]      This model is not on CISA's list of router security holes that criminals are using (list as of ${listDate}).`);
  }
  if (r.upnpOn) {
    lines.push(
      "[note]    UPnP appears to be on. It lets devices at home open doors in the router to the internet without asking. Game consoles and video calls use it, and so does malware. If nothing at home needs it, turn it off in the router's settings.",
    );
  } else if (!r.answeredUpnp) {
    lines.push("[ok]      The router did not answer a UPnP search, so UPnP is probably off.");
  }
  lines.push("", "What to do");
  const update = model
    ? `Look up the ${[maker, model].filter(Boolean).join(" ")} on the maker's support site and install the newest firmware.`
    : `Find the model on the router's label, look it up on ${maker ? `${maker}'s` : "the maker's"} support site, and install the newest firmware.`;
  const steps = [
    `${update} Turn on automatic updates if the router has them.`,
    "If the maker no longer releases updates for this model, replace the router. The FBI warns that routers too old for updates (often those from 2010 or earlier) are being taken over by criminals.",
    "Make sure the router's admin password is not the one printed on its label, and not \"admin\".",
    "Turn off remote management (changing settings from the internet) unless you use it.",
  ];
  if (r.matches.length) steps.unshift(`For each entry above, check the maker's security notice to see whether your hardware version is affected and which firmware fixes it.`);
  steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
  lines.push(
    "",
    `How this was checked: the router's own UPnP announcement and its network maker code, compared with a copy of CISA's list from ${listDate} bundled with this version. Nothing was sent outside your home network, and nothing logged into the router.`,
  );
  return lines.join("\n");
}
