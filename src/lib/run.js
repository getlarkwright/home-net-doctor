// Starts the few system programs this tool reads from. Each one is looked up at a fixed
// location (never through PATH or a shell) and always gets a fixed argument list, so nothing a
// caller types can turn into a command. Every run has a time limit.
import { execFile } from "node:child_process";
import fs from "node:fs";

const SYS32 = `${process.env.SystemRoot || "C:\\Windows"}\\System32\\`;

const PROGRAMS = {
  ping: {
    linux: ["/usr/bin/ping", "/bin/ping", "/usr/sbin/ping", "/sbin/ping"],
    darwin: ["/sbin/ping"],
    win32: [`${SYS32}PING.EXE`],
  },
  netstat: { darwin: ["/usr/sbin/netstat"] },
  arp: { darwin: ["/usr/sbin/arp"], win32: [`${SYS32}ARP.EXE`] },
  system_profiler: { darwin: ["/usr/sbin/system_profiler"] },
  route: { win32: [`${SYS32}ROUTE.EXE`] },
  netsh: { win32: [`${SYS32}netsh.exe`] },
  powershell: { win32: [`${SYS32}WindowsPowerShell\\v1.0\\powershell.exe`] },
  nmcli: { linux: ["/usr/bin/nmcli", "/bin/nmcli"] },
  iw: { linux: ["/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw", "/bin/iw"] },
};

const found = new Map();

export function programPath(name, platform = process.platform) {
  const key = `${platform}:${name}`;
  if (!found.has(key)) {
    const list = PROGRAMS[name]?.[platform] || [];
    found.set(key, list.find((p) => fs.existsSync(p)) || null);
  }
  return found.get(key);
}

/**
 * Run a known program. Resolves (never rejects) with
 * { ok, missing, code, stdout, stderr, timedOut }.
 */
export function run(name, args, { timeoutMs = 15000 } = {}) {
  const file = programPath(name);
  if (!file) return Promise.resolve({ ok: false, missing: true, code: null, stdout: "", stderr: "", timedOut: false });
  // English output where the system allows it, so the readers below see the words they expect.
  const env = process.platform === "win32" ? process.env : { ...process.env, LC_ALL: "C", LANG: "C" };
  return new Promise((resolve) => {
    execFile(
      file,
      args,
      { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, windowsHide: true, env, encoding: "utf8" },
      (err, stdout, stderr) => {
        resolve({
          ok: !err,
          missing: false,
          code: err ? (typeof err.code === "number" ? err.code : null) : 0,
          stdout: String(stdout || ""),
          stderr: String(stderr || ""),
          timedOut: Boolean(err && err.killed),
        });
      },
    );
  });
}
