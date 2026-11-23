// Text reports. The first part is written for the person; the measurements at the end are for a
// technician or the internet company. Wi-Fi network names, MAC addresses and the public IP address
// are never included.
import { diagnose, rateSignal, crowding } from "./diagnose.js";

const OS_NAME = { darwin: "Mac", win32: "Windows", linux: "Linux" };
const MARK = { problem: "[problem]", warning: "[warning]", note: "[note]   ", ok: "[ok]     " };
const v = (x, unit = "") => (x === null || x === undefined ? "?" : `${x}${unit}`);

function probeLine(name, p) {
  if (!p) return `  ${name}: not tested`;
  const how = p.method === "tcp" ? "TCP connect" : "ping";
  if (!p.received) return `  ${name}: ${how} ${p.sent} sent, 0 answered`;
  return `  ${name}: ${how} ${p.sent} sent, ${p.received} answered, avg ${v(p.avg, " ms")}, min ${v(p.min)}, max ${v(p.max)}, jitter ${v(p.jitter)}`;
}

function wifiLine(w) {
  if (!w?.connected) return null;
  const bits = [];
  if (w.signal !== null && w.signal !== undefined) bits.push(`signal ${w.signal} dBm${w.signalEstimated ? " (estimated from %)" : ""}`);
  if (w.noise !== null && w.noise !== undefined) bits.push(`noise ${w.noise} dBm`);
  if (w.band) bits.push(`${w.band} GHz${w.channel ? ` channel ${w.channel}` : ""}${w.width ? ` (${w.width} MHz)` : ""}`);
  if (w.phy) bits.push(w.phy);
  if (w.rate) bits.push(`${Math.round(w.rate)} Mbps link`);
  const c = crowding(w);
  if (c !== null) bits.push(`${c} other network${c === 1 ? "" : "s"} on the same channel`);
  return `  Wi-Fi${w.iface ? ` (${w.iface})` : ""}: ${bits.join(", ") || "connected"}`;
}

export function measurements(f) {
  const out = [];
  const when = new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC";
  out.push(`Measurements (${when}, ${OS_NAME[f.platform] || f.platform}${f.onWifi ? ", Wi-Fi" : ""}${f.routes?.viaVpn ? ", through a VPN" : ""})`);
  if (f.routes?.router) out.push(probeLine(`Router ${f.routes.router.ip} via ${f.routes.router.iface}`, f.router));
  else out.push("  Router: not found" + (f.routes?.viaVpn ? " (behind the VPN)" : ""));
  for (const p of f.internet?.all || []) out.push(probeLine(`Internet ${p.target} (${p.label})`, p));
  const w = wifiLine(f.wifi);
  if (w) out.push(w);
  if (f.dns) {
    const sys = f.dns.system?.works ? `works (${v(f.dns.system.ms, " ms")})` : `fails (${f.dns.system?.error})`;
    out.push(`  DNS, system lookup: ${sys}`);
    for (const s of f.dns.servers) {
      out.push(`  DNS, ${s.label} ${s.server}: ${s.works ? `works, new lookups ${v(s.ms, " ms")}${s.madeUp ? ", makes up answers" : ""}` : `fails (${s.error})`}`);
    }
  }
  if (f.https) out.push(`  Secure connection: ${f.https.works ? `works (${v(f.https.ms, " ms")})` : `fails (${f.https.error})`}`);
  if (f.ipv6) out.push(`  IPv6: ${!f.ipv6.has ? "no public IPv6 address" : f.ipv6.works ? `works (${v(f.ipv6.ms, " ms")})` : `broken (${f.ipv6.error})`}`);
  if (f.captive) {
    const c = f.captive;
    out.push(`  Sign-in page check: ${c.state === "clear" ? "none" : c.state === "portal" ? `HTTP ${c.status}${c.host ? ` to ${c.host}` : ""}` : `could not tell (${c.error})`}`);
  }
  if (f.routes?.vpnIfaces?.length) out.push(`  VPN or tunnel interfaces: ${f.routes.vpnIfaces.join(", ")}`);
  return out;
}

export function renderConnection(f) {
  const d = diagnose(f);
  const how = [OS_NAME[f.platform] || f.platform];
  if (f.onWifi) how.push("on Wi-Fi");
  else if (f.routes?.router) how.push("on a cable or other wired link");
  if (f.routes?.viaVpn) how.push("VPN on");
  const lines = [`Home Net Doctor: connection check (${how.join(", ")}; took ${f.seconds} s)`, "", `Verdict: ${d.verdict.title}`, "", "What I found"];
  const order = { problem: 0, warning: 1, note: 2, ok: 3 };
  for (const x of [...d.findings].sort((a, b) => order[a.level] - order[b.level])) lines.push(`${MARK[x.level]} ${x.text}`);
  if (d.steps.length) {
    lines.push("", "What to do");
    d.steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
  }
  lines.push("", ...measurements(f));
  return lines.join("\n");
}

const TIPS_24 = "2.4 GHz reaches farther but is slower and shared with more neighbors; 5 GHz (or 6 GHz) is much faster up close.";

export function renderWifi(w) {
  if (!w.present) return `Home Net Doctor: Wi-Fi check\n\nThis computer has no Wi-Fi, or its Wi-Fi is turned off.${w.note ? `\n${w.note}` : ""}`;
  if (w.connected === null) return `Home Net Doctor: Wi-Fi check\n\n${w.note}`;
  if (!w.connected) return "Home Net Doctor: Wi-Fi check\n\nWi-Fi is on, but this computer is not joined to a network.";
  const sig = rateSignal(w.signal);
  const lines = ["Home Net Doctor: Wi-Fi check", ""];
  if (sig) {
    const meaning = {
      strong: "Good for anything, including video calls and 4K streaming.",
      good: "Good for nearly everything.",
      fair: "Fine for browsing; video calls and gaming may stutter now and then.",
      weak: "Expect slowness and dropouts. Moving closer to the router or adding a mesh point will help.",
      "very weak": "Too weak to be reliable. Move closer to the router, or add a mesh point or access point near here.",
    }[sig.word];
    lines.push(`Signal: ${sig.word} (${w.signal} dBm${w.signalEstimated ? ", estimated" : ""}). ${meaning}`);
    lines.push("  Scale: -50 is excellent, -60 strong, -67 good, -75 fair, -82 weak, below that very weak.");
  } else lines.push("Signal: this computer did not report it.");
  if (w.noise !== null && w.noise !== undefined && w.signal !== null) {
    const snr = w.signal - w.noise;
    lines.push(`Noise: ${w.noise} dBm, so the signal is ${snr} dB above the noise (${snr >= 25 ? "comfortable" : snr >= 20 ? "acceptable" : "too little; something nearby is interfering"}).`);
  }
  if (w.band) lines.push(`Band: ${w.band} GHz${w.channel ? `, channel ${w.channel}` : ""}${w.width ? `, ${w.width} MHz wide` : ""}.${w.band === "2.4" ? ` ${TIPS_24}` : ""}`);
  if (w.phy) lines.push(`Wi-Fi standard: ${w.phy}${/ax|be/.test(w.phy) ? " (Wi-Fi 6 or newer)" : /ac/.test(w.phy) ? " (Wi-Fi 5)" : /n/.test(w.phy) ? " (Wi-Fi 4, older)" : ""}.`);
  if (w.rate) lines.push(`Link speed: ${Math.round(w.rate)} Mbps between this computer and the router. Your internet plan's speed is the other limit; whichever is lower wins.`);
  const c = crowding(w);
  if (c !== null) {
    const busy = w.band === "2.4" ? c >= 6 : c >= 4;
    lines.push(`Neighbors: ${c === 0 ? "no" : c} other network${c === 1 ? "" : "s"} nearby on the same${w.band === "2.4" ? " or overlapping" : ""} channel${busy ? ", which is crowded. Setting the router's channel to automatic, or picking a quieter one, can help." : "."}`);
  } else if (w.neighbors && !w.neighbors.length) {
    lines.push("Neighbors: this computer did not list nearby networks.");
  }
  return lines.join("\n");
}
