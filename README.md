# Home Net Doctor

Ask your AI assistant "why is my internet slow?" and get a real answer.

Home Net Doctor is an [MCP](https://modelcontextprotocol.io) server. It runs a few quick tests from
your own computer and tells you, in plain words, where the problem is:

- your **Wi-Fi** signal
- your **router**
- your **internet company**
- **DNS** (the lookups that turn website names into addresses)
- a **sign-in page** (hotel, café or guest Wi-Fi)
- a **VPN**
- or **one website** that is down

Then it says what to do about it. It can also check whether your router is a known security risk.

It only looks. It changes no settings, needs no admin password, and sends nothing back to anyone.

## What you can ask

- "Why is my internet so slow?"
- "Is it my Wi-Fi or is it Comcast?"
- "How good is my Wi-Fi signal here?"
- "Is Netflix down, or is it me?"
- "Video calls keep freezing. What's wrong?"
- "Is my router safe?"

## What you get back

An example: a laptop with weak Wi-Fi, two rooms away from its router.

```text
Verdict: The problem is the Wi-Fi between this computer and your router.

What I found
[problem] This computer → your router: 2 of 10 lost (20%), average 80 ms, slowest 388 ms. Healthy is under 10 ms with none lost.
[warning] This computer → the internet (Cloudflare): 2 of 10 lost (20%), average 100 ms. Most of this comes from the leg to your router, above.
[warning] Wi-Fi: weak signal (-79 dBm), 2.4 GHz channel 6, link speed 58 Mbps.
[warning] Wi-Fi channel is crowded: 7 other networks nearby use the same or overlapping channel.
[ok]      Name lookups (DNS): working; your DNS server answers new lookups in 48 ms (Cloudflare DNS: 19 ms).
[ok]      Secure connections: working (52 ms).

What to do
1. Move closer to the router, or move the router to an open, central spot: not in a cabinet, behind a TV or on the floor.
2. If the router has a separate 5 GHz network, join that one when you are in the same room or one room away.
3. Restart the router: unplug it for 30 seconds, plug it back in, and give it 2 to 3 minutes.
4. If the signal is weak in parts of the home, a mesh Wi-Fi system or a second access point usually fixes the dead spots.
```

Your assistant turns this into a normal answer. The full report also ends with the raw measurements, so you
can read them to your internet company if the problem turns out to be theirs.

## Install

You need [Node.js](https://nodejs.org) 20 or newer.

**Claude Code**

```bash
claude mcp add home-net-doctor -- npx -y home-net-doctor@0.2.0
```

**Claude Desktop, Cursor, VS Code and other MCP apps**: add this to the app's MCP settings:

```json
{
  "mcpServers": {
    "home-net-doctor": {
      "command": "npx",
      "args": ["-y", "home-net-doctor@0.2.0"]
    }
  }
}
```

**Without an AI app**, in a terminal:

```bash
npx -y home-net-doctor@0.2.0 check        # connection check, 10 to 25 seconds
npx -y home-net-doctor@0.2.0 wifi         # Wi-Fi signal report
npx -y home-net-doctor@0.2.0 site <url>   # is it this website, or my internet?
npx -y home-net-doctor@0.2.0 router       # router safety check
```

## The four tools

| Tool | What it does | Time |
| --- | --- | --- |
| `check_connection` | Pings your router and two public services, tests DNS, looks for a sign-in page, opens one secure connection, checks IPv6 and the Wi-Fi, then gives a verdict and steps. | 10 to 25 s |
| `check_wifi` | Signal strength with a plain rating, noise, 2.4 / 5 / 6 GHz band, channel, Wi-Fi standard, link speed, and how crowded the channel is. | a few s |
| `check_website` | Looks up a site, connects, and asks for its front page. Says whether it is down, refusing, broken, slow, has a certificate problem, or works fine from here. | a few s |
| `check_router` | Finds out who made your router and which model it is, whether UPnP is on, and whether that model is on the US government's list of router security holes that criminals are using ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)). | a few s |

It works on macOS, Windows and Linux.

## Safety and privacy

- **Read-only.** It never changes a setting, never logs into your router, and never tries passwords.
- **No admin rights.** Everything runs as you.
- **No telemetry.** Nothing is sent to us or anyone else.
- **Short, fixed list of outside addresses.** The connection check contacts only Cloudflare (1.1.1.1,
  `cp.cloudflare.com`, and its IPv6 address when you have IPv6) and Google (8.8.8.8). These are pings, DNS
  questions, one plain web request that should come back empty, and one secure connection that is closed
  straight away. The list is in [`src/lib/targets.js`](src/lib/targets.js).
- **Router check: stays at home.** It sends one UPnP search on your home network (to the router and to
  the standard UPnP group address), reads the description your router publishes about itself, and reads
  this computer's own address table. It never logs into the router and never tries a password. The CISA
  list is a copy bundled with each version (router makers and models only, refreshed for every release),
  so nothing is looked up online.
- **Websites: front page only.** `check_website` ignores any path you give it and asks only for `/`, so it
  can't trigger an action on a site or a device.
- **No network names.** Wi-Fi network names, MAC addresses and your public IP address are never put in
  a report.
- **No shell.** It starts a few built-in system programs (`ping`, `netstat` or `route`, the Wi-Fi report
  tool) from fixed locations with fixed arguments.

## What it can't do

- **It sees one computer.** If only your TV is slow, run it on a laptop standing next to the TV.
- **No speed test (yet).** A speed test sends a lot of data to an outside company, so it is left out on purpose.
  The ping, loss and DNS numbers usually show where a slowdown comes from without one.
- **Windows 11 hides Wi-Fi details** until location access is on for desktop apps (Settings > Privacy &
  security > Location). The rest of the check works without it, and the report says how to turn it on.
- **Some routers ignore pings.** It then measures the whole path to the internet and says so.
- **Many routers don't say their model.** If UPnP is off, the router check can usually only tell the maker
  (from its network hardware address), and asks you to read the model off the label.
- **A model on the CISA list is a warning, not proof.** Fixes often depend on the hardware version and the
  firmware, so the report points to the maker's notice for each entry.

## Development

```bash
npm install
npm test
```

The readers for each system's output are tested against recorded output in
[`test/fixtures`](test/fixtures): real captures from Linux and macOS with the addresses replaced by
documentation addresses, and Windows output in English and German. CI also runs every check for real on
Linux, macOS and Windows.

## License

MIT. Made by [Larkwright](https://github.com/getlarkwright).
