#!/usr/bin/env node
// Home Net Doctor: an MCP server that works out why the internet is slow or down, from the
// person's own computer, and explains it in plain words.
//
// Read-only: it changes no settings, needs no admin rights, and sends no telemetry. The outside
// addresses it contacts are listed in src/lib/targets.js.
//
//   home-net-doctor              run as an MCP server over stdio (what AI apps start)
//   home-net-doctor check        connection check, printed in the terminal
//   home-net-doctor wifi         Wi-Fi check
//   home-net-doctor site <url>   website check
import { createRequire } from "node:module";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import { gatherAll, getWifi } from "./lib/gather.js";
import { renderConnection, renderWifi } from "./lib/report.js";
import { checkWebsite, renderWebsite } from "./lib/website.js";

const VERSION = createRequire(import.meta.url)("../package.json").version;

const PLAIN =
  "The person asking is probably not technical: explain the verdict and the steps in plain words, " +
  "and only quote the measurements if they ask or need to pass them to their internet company.";

export const TOOLS = [
  {
    name: "check_connection",
    description:
      "Find out why the internet is slow, dropping or not working on this computer, and where the problem is: " +
      "the Wi-Fi, the router, the internet company, DNS (name lookups), a sign-in page, a VPN, or nothing at all. " +
      "Runs about 10-15 seconds of read-only tests from this computer (pings to the router and to two public " +
      "services, DNS lookups, one secure connection) and returns a verdict, what to do, and the measurements. " +
      PLAIN,
    inputSchema: { type: "object", properties: {} },
    annotations: { title: "Check my internet connection", readOnlyHint: true, openWorldHint: true },
    run: async () => renderConnection(await gatherAll()),
  },
  {
    name: "check_wifi",
    description:
      "Report on this computer's Wi-Fi connection: signal strength with a plain rating, noise, 2.4/5/6 GHz band, " +
      "channel, Wi-Fi standard, link speed, and how crowded the channel is. Takes a few seconds and contacts nothing " +
      "outside this computer. Network names are never read. " +
      PLAIN,
    inputSchema: { type: "object", properties: {} },
    annotations: { title: "Check my Wi-Fi signal", readOnlyHint: true, openWorldHint: false },
    run: async () => renderWifi(await getWifi()),
  },
  {
    name: "check_website",
    description:
      "Is it this website, or my internet? Looks up the site's name (and asks a public DNS service if that fails), " +
      "connects, and requests only its front page, then says whether the site is down, refusing, broken, slow, has " +
      "a certificate problem, or works fine from here. " +
      PLAIN,
    inputSchema: {
      type: "object",
      properties: { site: { type: "string", description: "A website name or address, e.g. netflix.com or https://example.com/page" } },
      required: ["site"],
    },
    annotations: { title: "Check a website", readOnlyHint: true, openWorldHint: true },
    run: async (a) => renderWebsite(await checkWebsite(typeof a.site === "string" ? a.site : "")),
  },
];

async function serve() {
  const server = new Server({ name: "home-net-doctor", version: VERSION }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS.map(({ name, description, inputSchema, annotations }) => ({ name, description, inputSchema, annotations })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const tool = TOOLS.find((t) => t.name === req.params.name);
    if (!tool) return { content: [{ type: "text", text: `Unknown tool: ${req.params.name}` }], isError: true };
    try {
      return { content: [{ type: "text", text: await tool.run(req.params.arguments || {}) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `${tool.name} failed: ${e.message}` }], isError: true };
    }
  });
  await server.connect(new StdioServerTransport());
}

const HELP = `home-net-doctor ${VERSION}: why is my internet slow?

As an MCP server (what Claude, Cursor and other AI apps run):
  npx -y home-net-doctor

In a terminal:
  npx -y home-net-doctor check        connection check (about 15 seconds)
  npx -y home-net-doctor wifi         Wi-Fi signal report
  npx -y home-net-doctor site <url>   is it this website or my internet?

Read-only. Changes no settings, needs no admin rights, sends no telemetry.
https://github.com/getlarkwright/home-net-doctor`;

const [cmd, ...rest] = process.argv.slice(2);
const print = (text) => process.stdout.write(text + "\n");

if (cmd === "--version" || cmd === "-v") print(VERSION);
else if (cmd === "--help" || cmd === "-h" || cmd === "help") print(HELP);
else if (cmd === "check") {
  process.stderr.write("Checking (about 15 seconds)...\n");
  print(await TOOLS[0].run({}));
} else if (cmd === "wifi") print(await TOOLS[1].run({}));
else if (cmd === "site") {
  if (!rest[0]) {
    print("Usage: home-net-doctor site <website>");
    process.exitCode = 1;
  } else print(await TOOLS[2].run({ site: rest[0] }));
} else if (cmd) {
  print(`Unknown command: ${cmd}\n\n${HELP}`);
  process.exitCode = 1;
} else if (process.stdin.isTTY) {
  // Started by hand with no command: an MCP server would just sit there waiting, so explain instead.
  print(HELP);
} else {
  await serve();
}
