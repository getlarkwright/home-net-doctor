// "Is it this website, or my internet?" Looks up the name, connects, and asks for the front page
// only: whatever path the person gives is ignored, so the check can never trigger an action on a
// device or site. Nothing is sent except a plain request for "/".
import net from "node:net";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";

import { tcpConnect } from "./gather.js";
import { PUBLIC_DNS, INTERNET_HOSTS, USER_AGENT } from "./targets.js";

const now = () => performance.now();
const r1 = (n) => (n === null || n === undefined ? null : Math.round(n));

export function parseSite(input) {
  let s = String(input || "").trim();
  if (!s) return { error: "Give a website, for example example.com or https://example.com." };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  let u;
  try {
    u = new URL(s);
  } catch {
    return { error: `"${input}" is not a website address.` };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { error: `Only web addresses (http or https) can be checked, not ${u.protocol.replace(":", "")}.` };
  if (u.username || u.password) return { error: "Leave any user name or password out of the address." };
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
  return { secure: u.protocol === "https:", host, port, ignoredPath: u.pathname !== "/" || Boolean(u.search) };
}

const PRIVATE_V4 = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;
const isPrivate = (ip) => (net.isIPv4(ip) ? PRIVATE_V4.test(ip) : /^(fe80|fc|fd|::1)/i.test(ip));

async function lookupBoth(host) {
  const t0 = now();
  let system;
  try {
    const all = await dns.promises.lookup(host, { all: true });
    system = { ok: true, addresses: all.map((a) => a.address), ms: r1(now() - t0) };
  } catch (e) {
    system = { ok: false, error: e.code || e.message };
  }
  if (system.ok) return { system };
  // Ask a public DNS service too, to tell "the name doesn't exist" from "your DNS can't find it".
  const resolver = new dns.promises.Resolver({ timeout: 3000, tries: 1 });
  resolver.setServers([PUBLIC_DNS[0].ip]);
  let publicDns;
  try {
    const a = await resolver.resolve4(host).catch(async (e) => {
      if (e.code === "ENODATA") return resolver.resolve6(host);
      throw e;
    });
    publicDns = { ok: true, addresses: a };
  } catch (e) {
    publicDns = { ok: false, error: e.code || e.message };
  }
  return { system, publicDns };
}

function fetchFrontPage({ secure, host, port, address }) {
  return new Promise((resolve) => {
    const t0 = now();
    const timing = {};
    const mod = secure ? https : http;
    const req = mod.request({
      host: address,
      port,
      path: "/",
      method: "GET",
      servername: net.isIP(host) ? undefined : host,
      headers: { host: port === (secure ? 443 : 80) ? host : `${host}:${port}`, "user-agent": USER_AGENT, accept: "text/html,*/*" },
      timeout: 10000,
      agent: false,
    });
    req.on("socket", (sock) => {
      sock.once("connect", () => (timing.connect = r1(now() - t0)));
      sock.once("secureConnect", () => {
        timing.secure = r1(now() - t0);
        const cert = sock.getPeerCertificate?.();
        if (cert?.valid_to) timing.certDaysLeft = Math.floor((Date.parse(cert.valid_to) - Date.now()) / 86400000);
      });
    });
    req.once("response", (res) => {
      timing.firstByte = r1(now() - t0);
      const location = res.headers.location || null;
      res.destroy();
      req.destroy();
      resolve({ ok: true, status: res.statusCode, location, ...timing });
    });
    req.once("timeout", () => {
      req.destroy();
      resolve({ ok: false, error: timing.connect ? "the server connected but never answered" : "timeout", ...timing });
    });
    req.once("error", (e) => resolve({ ok: false, error: e.code || e.message, ...timing }));
    req.end();
  });
}

export async function checkWebsite(input) {
  const site = parseSite(input);
  if (site.error) return { input, error: site.error };
  const [baseline, names] = await Promise.all([
    tcpConnect(INTERNET_HOSTS[0].ip, 443, 3000).then((a) => (a.ok ? a : tcpConnect(INTERNET_HOSTS[1].ip, 443, 3000))),
    net.isIP(site.host) ? Promise.resolve({ system: { ok: true, addresses: [site.host], ms: 0, literal: true } }) : lookupBoth(site.host),
  ]);
  const result = { input, site, internet: baseline.ok, names };
  if (!names.system.ok) return result;
  // Try up to two of the addresses, IPv4 first, so one dead address does not decide the answer.
  const addrs = [...names.system.addresses].sort((a, b) => (net.isIPv4(b) ? 1 : 0) - (net.isIPv4(a) ? 1 : 0)).slice(0, 2);
  result.private = addrs.every(isPrivate);
  for (const address of addrs) {
    const page = await fetchFrontPage({ ...site, address });
    result.page = { ...page, address };
    if (page.ok) break;
  }
  return result;
}

const TLS_WORDS = {
  CERT_HAS_EXPIRED: "the site's security certificate has expired (or this computer's date is wrong)",
  CERT_NOT_YET_VALID: "the site's security certificate is not valid yet, which usually means this computer's date is wrong",
  ERR_TLS_CERT_ALTNAME_INVALID: "the site's security certificate is for a different name",
  DEPTH_ZERO_SELF_SIGNED_CERT: "the site uses a home-made (self-signed) certificate",
  SELF_SIGNED_CERT_IN_CHAIN: "the certificate chain is not trusted; something may be intercepting secure connections (antivirus, a work filter)",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "the site's certificate can't be verified (the site may be missing part of its certificate chain)",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "the certificate's issuer is not trusted; something may be intercepting secure connections",
};

export function renderWebsite(r) {
  if (r.error) return r.error;
  const s = r.site;
  const name = s.port === (s.secure ? 443 : 80) ? s.host : `${s.host}:${s.port}`;
  const lines = [`Home Net Doctor: website check for ${name}`, ""];
  const say = (verdict, ...rest) => lines.push(`Verdict: ${verdict}`, ...(rest.length ? ["", ...rest] : []));
  const sys = r.names.system;
  const pub = r.names.publicDns;

  if (!sys.ok) {
    if (!r.internet) say("This computer can't reach the internet at all right now, so the website can't be tested. Ask me to run the connection check.");
    else if (pub?.ok) say(`Your DNS can't find ${s.host}, but a public DNS service can. The site exists; the name lookup on your network is the problem.`, "Restarting the router often fixes this. If not, switching to a public DNS service such as Cloudflare or Google will.");
    else if (pub && /ENOTFOUND/.test(pub.error)) say(`The name ${s.host} does not exist. Check the spelling.`);
    else say(`Nobody can look up ${s.host} right now (${pub?.error || sys.error}). The site's own DNS is probably broken, which only the site's owner can fix.`);
    return lines.join("\n");
  }

  const p = r.page;
  const where = r.private ? " (an address on a local network)" : "";
  if (p.ok) {
    const secs = p.firstByte < 1000 ? `${p.firstByte} ms` : `${(p.firstByte / 1000).toFixed(1)} s`;
    const slow = p.firstByte > 3000;
    if (p.status >= 500) say(`The site is up but broken right now: its server answered with an error (${p.status}). That is on the site's side; try again later.`);
    else if (p.status === 403 || p.status === 429) say(`The site answered but refused this check (${p.status}). Many sites turn away automated checks, so this does not mean it is down. If it also fails in your browser, the site may be blocking your network.`);
    else if (p.status >= 400) say(`The site is up and answered (${p.status} for its front page) in ${secs}.`);
    else say(`The site works from here: it answered in ${secs}${slow ? ", which is slow" : ""}.${p.status >= 300 && p.location ? ` It sends visitors on to ${(() => { try { return new URL(p.location, `http://${s.host}`).host; } catch { return "another address"; } })()}.` : ""}`);
    if (!r.internet) lines.push("", "Note: the general internet test did not answer, but this site did.");
    if (p.status < 500 && !slow) lines.push("", "If it still fails for you, the problem is likely the app or browser (try another browser or a private window), or the site is blocking you.");
  } else if (!r.internet) {
    say("This computer can't reach the internet at all right now, so the website can't be tested. Ask me to run the connection check.");
  } else if (TLS_WORDS[p.error]) {
    say(`The site answers, but ${TLS_WORDS[p.error]}. Browsers will warn about it or refuse to open it.`);
  } else if (p.error === "ECONNREFUSED") {
    say(`The site's server${where} is reachable but refuses connections on port ${s.port}. The website is down or not running there.`);
  } else if (/timeout|EHOSTUNREACH|ENETUNREACH|never answered/i.test(p.error)) {
    say(`The site's server${where} is not answering, while the rest of the internet works from here. The site is most likely down, or it is blocking your network.`);
  } else {
    say(`The site could not be reached (${p.error}), while the rest of the internet works from here.`);
  }

  lines.push("", "Details");
  lines.push(`  Name lookup: ${sys.literal ? "not needed (an IP address was given)" : `${sys.addresses.length} address${sys.addresses.length === 1 ? "" : "es"} in ${sys.ms} ms`}`);
  if (p) {
    lines.push(`  Tried ${p.address} port ${s.port}: ${p.ok ? `HTTP ${p.status}` : p.error}`);
    if (p.connect !== undefined) lines.push(`  Connected in ${p.connect} ms${p.secure !== undefined ? `, secure in ${p.secure} ms` : ""}${p.firstByte !== undefined ? `, first answer in ${p.firstByte} ms` : ""}`);
    if (p.certDaysLeft !== undefined && p.certDaysLeft < 21) lines.push(`  Security certificate: ${p.certDaysLeft < 0 ? "expired" : `expires in ${p.certDaysLeft} days`}`);
  }
  if (s.ignoredPath) lines.push("  Only the front page was checked; the rest of the address was left out on purpose.");
  return lines.join("\n");
}
