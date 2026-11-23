import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { parseSite, checkWebsite, renderWebsite } from "../src/lib/website.js";

test("addresses: scheme, port and path handling", () => {
  assert.deepEqual(parseSite("example.com"), { secure: true, host: "example.com", port: 443, ignoredPath: false });
  assert.deepEqual(parseSite("http://example.com:8080/a/b?c=1"), { secure: false, host: "example.com", port: 8080, ignoredPath: true });
  assert.equal(parseSite("https://[2001:db8::1]/").host, "2001:db8::1");
  assert.match(parseSite("ftp://example.com").error, /Only web addresses/);
  assert.match(parseSite("https://user:pw@example.com").error, /user name or password/);
  assert.match(parseSite("").error, /Give a website/);
});

test("only the front page is requested, whatever path is given", async () => {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push(req.url);
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  try {
    const r = await checkWebsite(`http://127.0.0.1:${port}/admin/reboot?confirm=yes`);
    assert.equal(r.page.ok, true);
    assert.equal(r.page.status, 200);
    assert.deepEqual(seen, ["/"]);
    const text = renderWebsite(r);
    assert.match(text, /Only the front page was checked/);
    // With internet the verdict is "works"; on an offline machine the note says the general test failed.
    assert.match(text, /works from here|general internet test/);
  } finally {
    server.close();
  }
});

test("a closed port is reported as refusing, and a server error as broken", async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(503);
    res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  try {
    const broken = renderWebsite(await checkWebsite(`http://127.0.0.1:${port}`));
    assert.match(broken, /broken right now.*503/);
  } finally {
    server.close();
  }
  const refused = renderWebsite(await checkWebsite(`http://127.0.0.1:${port}`));
  assert.match(refused, /refuses connections|can't reach the internet/);
});
