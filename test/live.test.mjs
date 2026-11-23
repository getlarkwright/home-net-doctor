// Runs against the real system the tests are on (Linux, macOS and Windows in CI), so the readers
// meet real program output, not only the recorded files.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { ping, getRoutes, getWifi, getInterfaces } from "../src/lib/gather.js";
import { renderWifi } from "../src/lib/report.js";
import { programPath } from "../src/lib/run.js";

test("ping to this computer is read correctly on this system", { skip: !programPath("ping") && "no ping program here" }, async () => {
  const p = await ping("127.0.0.1", 2);
  assert.ok(p, "ping should be usable");
  assert.equal(p.sent, 2);
  assert.equal(p.received, 2, `expected 2 replies, got ${JSON.stringify(p)}`);
  assert.ok(p.avg >= 0 && p.avg < 50);
});

test("ping refuses anything that is not an IP address", async () => {
  assert.equal(await ping("example.com; rm -rf /"), null);
});

test("the default route on this system is found", async () => {
  const r = await getRoutes(getInterfaces());
  assert.equal(r.error, null);
  assert.ok(r.router || r.primaryIface, `no default route found: ${JSON.stringify(r)}`);
  if (r.router) assert.match(r.router.ip, /^\d+\.\d+\.\d+\.\d+$/);
});

test("Wi-Fi reading does not fail, with or without Wi-Fi", async () => {
  const w = await getWifi();
  assert.equal(typeof w.present, "boolean");
  assert.match(renderWifi(w), /^Home Net Doctor: Wi-Fi check/);
});

function mcp(messages) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL("../src/index.js", import.meta.url))], {
      stdio: ["pipe", "pipe", "inherit"],
    });
    let out = "";
    const replies = new Map();
    child.stdout.on("data", (d) => {
      out += d;
      let i;
      while ((i = out.indexOf("\n")) >= 0) {
        const line = out.slice(0, i);
        out = out.slice(i + 1);
        if (!line.trim()) continue;
        const msg = JSON.parse(line);
        if (msg.id !== undefined) replies.set(msg.id, msg);
        if (replies.size === messages.filter((m) => m.id !== undefined).length) {
          child.kill();
          resolve(replies);
        }
      }
    });
    child.on("error", reject);
    setTimeout(() => {
      child.kill();
      reject(new Error("MCP server did not answer in time"));
    }, 60000).unref();
    for (const m of messages) child.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...m }) + "\n");
  });
}

test("the MCP server lists its four read-only tools and answers calls", async () => {
  const r = await mcp([
    { id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } } },
    { method: "notifications/initialized" },
    { id: 2, method: "tools/list" },
    { id: 3, method: "tools/call", params: { name: "check_wifi", arguments: {} } },
    { id: 4, method: "tools/call", params: { name: "check_website", arguments: { site: "ftp://example.com" } } },
  ]);
  assert.equal(r.get(1).result.serverInfo.name, "home-net-doctor");
  const tools = r.get(2).result.tools;
  assert.deepEqual(tools.map((t) => t.name), ["check_connection", "check_wifi", "check_website", "check_router"]);
  assert.ok(tools.every((t) => t.annotations.readOnlyHint === true));
  assert.match(r.get(3).result.content[0].text, /^Home Net Doctor: Wi-Fi check/);
  assert.match(r.get(4).result.content[0].text, /Only web addresses/);
});
