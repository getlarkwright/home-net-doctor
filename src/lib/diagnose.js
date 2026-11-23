// Turns the gathered facts into a verdict a non-technical person can act on. Pure: facts in,
// { verdict, findings, steps } out, so every rule can be tested with made-up facts.

export const LIMITS = {
  router: { lossProblem: 0.2, lossWarn: 0.1, avgProblem: 100, avgWarn: 30, jitterWarn: 25, spikeWarn: 200 },
  internet: { lossProblem: 0.2, lossWarn: 0.1, avgProblem: 250, avgWarn: 100 },
  dns: { slowWarn: 300 },
  wifi: { rateWarn: 30, crowded24: 6, crowded5: 4 },
  clockSkewWarnSec: 120,
};

const STEP = {
  restartRouter: "Restart the router: unplug it for 30 seconds, plug it back in, and give it 2 to 3 minutes.",
  restartBoth:
    "Restart the modem and the router: unplug both for 30 seconds, plug the modem in first, wait until its lights settle (about 2 minutes), then plug in the router.",
  moveCloser: "Move closer to the router, or move the router to an open, central spot: not in a cabinet, behind a TV or on the floor.",
  use5: "If the router has a separate 5 GHz network, join that one when you are in the same room or one room away. 2.4 GHz reaches farther but is slower and more crowded.",
  mesh: "If the signal is weak in parts of the home, a mesh Wi-Fi system or a second access point usually fixes the dead spots.",
  cable: "Try a different network cable, or a different port on the router.",
  outage: "Check your internet company's outage page or app.",
  callIsp: "If it keeps happening, call your internet company and read them the measurements at the end of this report.",
  toggle: "Turn Wi-Fi off and on again on this computer, or unplug the network cable and plug it back in.",
  forget: "If that does not help, forget the network on this computer and join it again.",
  ownNetwork: "Make sure this computer is on your own home network, not a neighbor's or a guest network.",
  join: "Turn on Wi-Fi and join your network, or plug in a network cable.",
  signIn: "Open a web browser and go to any website. The sign-in page should appear: accept the terms or log in, then try again.",
  dnsSwitch:
    "Switch the router (or just this computer) to a public DNS service such as Cloudflare (1.1.1.1) or Google (8.8.8.8). The setting is usually called DNS, in the router's settings page or your internet company's app.",
  vpnOff: "Turn the VPN off for a minute and run this check again. If things get faster, the VPN is the bottleneck: try a closer VPN server, or contact the VPN provider.",
  vpnRestart: "Disconnect the VPN and connect it again. If it still does not work, turn it off and check whether the internet works without it.",
  ipv6: "Restart the router. If IPv6 is still broken afterwards, ask your internet company to fix it, or turn IPv6 off in the router's settings.",
  clock: "Set this computer's date and time to update automatically (in Date & Time settings).",
  filter: "If you use a web filter, parental-control app or security app, turn it off for a minute and check again.",
  again: "If the internet is only slow some of the time, run this check again while it is slow.",
  busy: "If other devices are streaming, gaming or downloading big files, pause them and check again. A busy network answers slowly.",
  hotspot: "If this is a phone's hotspot, some delay is normal: phones save power between messages. Keep the phone close by and plugged in.",
  site: "If one website or app is the problem, ask me to check that website.",
};

export function rateSignal(dbm) {
  if (dbm === null || dbm === undefined || !Number.isFinite(dbm)) return null;
  if (dbm >= -60) return { word: "strong", level: "ok" };
  if (dbm >= -67) return { word: "good", level: "ok" };
  if (dbm >= -75) return { word: "fair", level: "note" };
  if (dbm >= -82) return { word: "weak", level: "warning" };
  return { word: "very weak", level: "warning" };
}

/** How many other networks share (2.4 GHz: overlap) this Wi-Fi channel. */
export function crowding(wifi) {
  if (!wifi?.channel || !wifi.neighbors?.length) return null;
  const near = wifi.neighbors.filter((n) => {
    if (!n.channel) return false;
    if (wifi.band === "2.4") return n.channel <= 14 && Math.abs(n.channel - wifi.channel) <= 4;
    return n.channel === wifi.channel && (n.band === wifi.band || n.band === null);
  });
  return near.length;
}

const pct = (x) => `${Math.round(x * 100)}%`;
const ms = (x) => (x === null || x === undefined ? "?" : `${x < 10 ? x : Math.round(x)} ms`);
const lostText = (p) => (p.received === p.sent ? "none lost" : `${p.sent - p.received} of ${p.sent} lost (${pct(p.loss)})`);

export function diagnose(f) {
  const findings = [];
  const add = (level, area, text) => findings.push({ level, area, text });
  const steps = [];
  const step = (...keys) => keys.forEach((k) => !steps.includes(STEP[k]) && steps.push(STEP[k]));

  const wifi = f.wifi || {};
  const onWifi = Boolean(f.onWifi);
  const vpnOn = Boolean(f.routes?.viaVpn || f.routes?.vpnIfaces?.length);
  const viaVpn = Boolean(f.routes?.viaVpn);
  const router = f.router;
  const routerKnown = Boolean(f.routes?.router);
  const routerReach = Boolean(router && router.received > 0);
  const inet = f.internet?.best || null;
  const inetReach = Boolean(inet && inet.received > 0);
  const httpsOk = Boolean(f.https?.works);
  const sig = onWifi || wifi.connected ? rateSignal(wifi.signal) : null;
  const strongSignal = Boolean(onWifi && sig && (sig.word === "strong" || sig.word === "good"));
  // Steps for a slow or lossy leg to the router, depending on what the Wi-Fi signal says.
  const localSteps = () => {
    if (!onWifi) return step("cable", "restartRouter");
    if (strongSignal) return step("restartRouter", "busy", "hotspot");
    step("moveCloser");
    if (wifi.band === "2.4") step("use5");
    step("restartRouter", "mesh");
  };
  const crowd = crowding(wifi);
  const yourDns = (f.dns?.servers || []).filter((s) => s.kind === "yours");
  const publicDns = (f.dns?.servers || []).filter((s) => s.kind === "public");
  const yoursWork = yourDns.some((s) => s.works);
  const publicWork = publicDns.some((s) => s.works);
  const systemDnsWorks = Boolean(f.dns?.system?.works);

  // ---- facts, one line each ---------------------------------------------------------------

  if (routerKnown && router) {
    if (!routerReach && inetReach) {
      add("note", "router", "Your router does not answer test messages (some are set up that way), so I could only measure the whole path to the internet.");
    } else if (!routerReach) {
      add("problem", "router", "This computer → your router: no answer at all.");
    } else if (router.method === "tcp") {
      add(
        "ok",
        "router",
        `This computer → your router: it answered (about ${ms(router.avg)}). It does not answer pings, so lost messages on this leg can't be measured.`,
      );
    } else {
      const L = LIMITS.router;
      const bad = router.loss >= L.lossProblem || router.avg >= L.avgProblem;
      const warn = !bad && (router.loss >= L.lossWarn || router.avg >= L.avgWarn || router.jitter >= L.jitterWarn || router.max >= L.spikeWarn);
      const healthy = onWifi ? "under 10 ms with none lost" : "a few ms with none lost";
      add(
        bad ? "problem" : warn ? "warning" : "ok",
        "router",
        `This computer → your router: ${lostText(router)}, average ${ms(router.avg)}, slowest ${ms(router.max)}. Healthy is ${healthy}.`,
      );
    }
  } else if (viaVpn) {
    add("note", "router", "Your home router is hidden behind the VPN, so I could not test the leg to it separately.");
  }

  if (onWifi || wifi.connected) {
    if (sig) {
      const parts = [`${sig.word} signal (${wifi.signal} dBm${wifi.signalEstimated ? ", estimated" : ""})`];
      if (wifi.band) parts.push(`${wifi.band} GHz${wifi.channel ? ` channel ${wifi.channel}` : ""}`);
      if (wifi.rate) parts.push(`link speed ${Math.round(wifi.rate)} Mbps`);
      add(sig.level, "wifi", `Wi-Fi: ${parts.join(", ")}.`);
      if (wifi.noise !== null && wifi.noise !== undefined && wifi.signal - wifi.noise < 20) {
        add("warning", "wifi", `Wi-Fi: a lot of radio noise around (signal only ${wifi.signal - wifi.noise} dB above the noise; 25 or more is comfortable).`);
      }
    } else if (wifi.connected) {
      add("note", "wifi", "Wi-Fi: connected, but this computer did not report the signal strength.");
    }
    if (wifi.rate && wifi.rate < LIMITS.wifi.rateWarn) {
      add("warning", "wifi", `Wi-Fi link speed is only ${Math.round(wifi.rate)} Mbps between this computer and the router.`);
    }
    if (crowd !== null) {
      const limit = wifi.band === "2.4" ? LIMITS.wifi.crowded24 : LIMITS.wifi.crowded5;
      if (crowd >= limit) add(wifi.band === "2.4" ? "warning" : "note", "wifi", `Wi-Fi channel is crowded: ${crowd} other networks nearby use the same or overlapping channel.`);
    }
  } else if (wifi.note) {
    add("note", "wifi", wifi.note);
  }

  if (inet) {
    const L = LIMITS.internet;
    if (!inetReach) {
      add("problem", "internet", `This computer → the internet: no answer from ${f.internet.all.map((p) => p.label).join(" or ")}.`);
    } else {
      const bad = inet.loss >= L.lossProblem || inet.avg >= L.avgProblem;
      const warn = !bad && (inet.loss >= L.lossWarn || inet.avg >= L.avgWarn);
      // Everything to the internet passes the router first. When that leg is already losing
      // messages or slow, and the internet numbers are not clearly worse, the trouble is local.
      const R = LIMITS.router;
      const fromLocal =
        (bad || warn) &&
        routerReach &&
        router.method === "ping" &&
        (router.loss >= R.lossWarn || router.avg >= R.avgWarn) &&
        inet.loss <= router.loss + 0.1 &&
        inet.avg - router.avg <= 50;
      add(
        fromLocal ? "warning" : bad ? "problem" : warn ? "warning" : "ok",
        "internet",
        `This computer → the internet (${inet.label}): ${lostText(inet)}, average ${ms(inet.avg)}.` +
          (fromLocal ? " Most of this comes from the leg to your router, above." : " Typical home internet is under 50 ms with none lost."),
      );
    }
  }

  if (f.dns) {
    const mine = yourDns.find((s) => s.works);
    const fastestPublic = publicDns.filter((s) => s.works && s.ms !== null).sort((a, b) => a.ms - b.ms)[0];
    if (!systemDnsWorks && !yoursWork) {
      add("problem", "dns", `Name lookups (DNS): failing${publicWork ? ", although public DNS services answer fine" : ""}.`);
    } else if (!systemDnsWorks || (yourDns.length && !yoursWork)) {
      add("warning", "dns", "Name lookups (DNS): some lookups fail.");
    } else if (mine?.ms !== null && mine?.ms !== undefined) {
      const slow = mine.ms >= LIMITS.dns.slowWarn && fastestPublic && fastestPublic.ms < mine.ms / 2;
      add(
        slow ? "warning" : "ok",
        "dns",
        `Name lookups (DNS): working; ${mine.label} answers new lookups in ${ms(mine.ms)}${fastestPublic ? ` (${fastestPublic.label}: ${ms(fastestPublic.ms)})` : ""}.`,
      );
    } else {
      add("ok", "dns", "Name lookups (DNS): working.");
    }
    if (yourDns.some((s) => s.madeUp)) {
      add(
        "note",
        "dns",
        "Your DNS server makes up answers for website names that don't exist (often to show search or ad pages). It doesn't slow you down, but a public DNS service avoids it.",
      );
    }
  }

  if (f.https) {
    if (httpsOk) add("ok", "https", `Secure connections: working (${ms(f.https.ms)}).`);
    else if (f.https.clock) add("problem", "https", "Secure connections fail because this computer's date or time is wrong.");
    else if (f.https.inspected)
      add("note", "https", "Secure connections are being opened up and inspected by something on this computer or network, often antivirus or a work filter.");
    else add(inetReach ? "problem" : "note", "https", `Secure connections: failing (${f.https.error}).`);
  }

  if (f.captive?.state === "portal" && f.captive.status >= 300 && f.captive.status < 400) {
    add("problem", "portal", `A sign-in page is in the way${f.captive.host ? ` (it sends web traffic to ${f.captive.host})` : ""}.`);
  } else if (f.captive?.state === "portal") {
    add("note", "portal", "Something on this network answers plain (non-secure) web requests in place of the real server, such as a web filter.");
  }
  const skew = f.captive?.clockSkewSec;
  if (skew !== null && skew !== undefined && Math.abs(skew) >= LIMITS.clockSkewWarnSec) {
    add("warning", "clock", `This computer's clock is off by about ${Math.round(Math.abs(skew) / 60)} minutes. Secure websites can refuse to load when it is far off.`);
  }

  if (f.ipv6?.has) {
    if (f.ipv6.works) add("ok", "ipv6", "IPv6: working.");
    else
      add(
        "warning",
        "ipv6",
        "IPv6 is half-working: this computer has an IPv6 address but can't reach the internet over it. Some apps wait for it to time out first, which makes pages slow to start loading.",
      );
  }

  if (vpnOn) {
    const names = f.routes?.vpnIfaces?.length ? ` (${f.routes.vpnIfaces.join(", ")})` : "";
    add("note", "vpn", viaVpn ? `A VPN is on${names} and all internet traffic goes through it, so its speed limits yours.` : `A VPN or tunnel is connected${names}.`);
  }

  // ---- verdict: the first rule that matches decides -----------------------------------------

  const has = (level, area) => findings.some((x) => x.level === level && (!area || x.area === area));
  let verdict;

  if (f.routes?.error && !routerKnown && !inetReach) {
    verdict = { code: "unsupported", title: f.routes.error };
  } else if (!f.interfaces?.hasAny && !f.interfaces?.selfAssignedOnly) {
    verdict = {
      code: "no_network",
      title: wifi.present && !wifi.connected ? "This computer's Wi-Fi is not joined to any network." : "This computer is not connected to any network.",
    };
    step("join", "toggle");
  } else if (f.interfaces?.selfAssignedOnly) {
    verdict = { code: "no_address", title: "This computer is connected, but the router did not give it an address, so nothing can get through." };
    step("toggle", "restartRouter", "forget");
  } else if (has("problem", "portal")) {
    verdict = { code: "portal", title: "This network wants you to sign in first, like a hotel, café, airport or guest Wi-Fi page." };
    step("signIn");
  } else if (!routerKnown && !viaVpn && !inetReach) {
    verdict = { code: "no_route", title: "This computer has an address but no way out to the internet." };
    step("toggle", "restartRouter");
  } else if (routerKnown && !routerReach && !inetReach) {
    verdict = {
      code: "router_unreachable",
      title: onWifi ? "This computer can't reach your router over Wi-Fi, so nothing gets out." : "This computer can't reach your router, so nothing gets out.",
    };
    if (onWifi) step("ownNetwork");
    step("toggle", "restartRouter");
    if (!onWifi) step("cable");
  } else if (has("problem", "router")) {
    verdict = {
      code: onWifi ? "wifi" : "local_link",
      title: !onWifi
        ? "The problem is the connection between this computer and your router."
        : strongSignal
          ? "The problem is between this computer and your router. The Wi-Fi signal is strong, so distance is not the cause: the router (or hotspot) is slow to answer."
          : "The problem is the Wi-Fi between this computer and your router.",
    };
    localSteps();
  } else if (!inetReach && !httpsOk) {
    verdict = viaVpn
      ? { code: "vpn_down", title: "Nothing gets through the VPN. Either the VPN is stuck or the internet behind it is down." }
      : { code: "internet_down", title: "Your router answers, but the internet past it is down. That points to the modem or your internet company." };
    if (viaVpn) step("vpnRestart");
    step("restartBoth", "outage", "callIsp");
  } else if (has("problem", "internet")) {
    verdict = {
      code: "isp",
      title: viaVpn
        ? "Your Wi-Fi and router look fine; the slowdown is past them, in the VPN or at your internet company."
        : "Your Wi-Fi and router look fine; the slowdown is past your router, on your internet company's side.",
    };
    if (viaVpn) step("vpnOff");
    step("restartBoth", "outage", "callIsp");
  } else if (has("problem", "dns")) {
    verdict = { code: "dns", title: "The internet works, but name lookups (DNS) are failing, so websites won't load by name." };
    step("restartRouter", "dnsSwitch");
  } else if (has("problem", "https")) {
    const clock = Boolean(f.https?.clock);
    verdict = clock
      ? { code: "clock", title: "This computer's date or time is wrong, so secure websites won't load." }
      : { code: "https_blocked", title: "Basic internet works, but secure websites can't connect. A firewall, filter or security app may be blocking them." };
    if (clock) step("clock");
    else {
      if (vpnOn) step("vpnOff");
      step("filter", "restartRouter");
    }
  } else if (findings.some((x) => x.level === "warning")) {
    const top = ["router", "wifi", "internet", "dns", "ipv6", "clock"].find((a) => has("warning", a));
    const titles = {
      router: !onWifi
        ? "It works, but the connection to your router is unsteady."
        : strongSignal
          ? "It works, but your router (or hotspot) is slow to answer, even though the Wi-Fi signal is strong. That can make things choppy."
          : "It works, but the Wi-Fi to your router is unsteady, which can make things slow or choppy.",
      wifi: "It works, but the Wi-Fi signal is not great, which can make things slow.",
      internet: "It works, but the internet past your router is a bit slow or unsteady.",
      dns: "It works, but name lookups (DNS) are slow, which makes every new website slow to start.",
      ipv6: "It works, but broken IPv6 can make websites slow to start loading.",
      clock: "It works, but this computer's clock is off.",
    };
    verdict = { code: `warning_${top}`, title: titles[top] };
    if (top === "router") localSteps();
    if (top === "wifi") {
      step("moveCloser");
      if (wifi.band === "2.4") step("use5");
      step("mesh");
    }
    if (top === "internet") {
      if (viaVpn) step("vpnOff");
      step("restartBoth", "again", "callIsp");
    }
    if (viaVpn && has("warning", "internet")) step("vpnOff");
    if (has("warning", "dns")) step("dnsSwitch");
    if (has("warning", "ipv6")) step("ipv6");
    if (has("warning", "clock")) step("clock");
    step("again");
  } else {
    verdict = { code: "healthy", title: "Everything looks healthy from this computer." };
    if (viaVpn) step("vpnOff");
    step("again", "site");
  }

  return { verdict, findings, steps };
}
