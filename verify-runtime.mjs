import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server.address().port;
}

async function close(server) {
  if (server.listening) await new Promise((resolve) => server.close(resolve));
}

async function unusedPort() {
  const reservation = net.createServer();
  const port = await listen(reservation);
  await close(reservation);
  return port;
}

async function api(port, path, method = "GET", body) {
  const response = await new Promise((resolve, reject) => {
    const request = http.request({
      hostname: "127.0.0.1", port, path, method,
      headers: body ? { "Content-Type": "application/json" } : {},
    }, resolve);
    request.on("error", reject);
    request.setTimeout(1000, () => request.destroy(new Error(`${method} ${path} timed out`)));
    request.end(body ? JSON.stringify(body) : undefined);
  });
  response.setEncoding("utf8");
  let text = "";
  for await (const chunk of response) text += chunk;
  assert.ok(response.statusCode >= 200 && response.statusCode < 300,
    `${method} ${path}: HTTP ${response.statusCode}`);
  return text ? JSON.parse(text) : undefined;
}

async function waitForGroup(child, port, path, expected) {
  let lastError;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error("Mihomo exited during startup");
    }
    try {
      assert.deepEqual((await api(port, path)).all, expected);
      return;
    } catch (error) {
      lastError = error;
      await delay(50);
    }
  }
  throw new Error(`Mihomo group did not become ready: ${lastError.message}`);
}

function requestThroughProxy(port, targetPort) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      hostname: "127.0.0.1", port, method: "CONNECT", path: `review.invalid:${targetPort}`,
    });
    request.on("error", reject);
    request.setTimeout(3000, () => request.destroy(new Error("CONNECT timed out")));
    request.on("connect", (response, socket) => {
      if (response.statusCode !== 200) {
        socket.destroy();
        reject(new Error(`CONNECT returned HTTP ${response.statusCode}`));
        return;
      }
      let body = "";
      socket.setEncoding("utf8");
      socket.setTimeout(3000, () => socket.destroy(new Error("Direct request timed out")));
      socket.on("data", (chunk) => { body += chunk; });
      socket.on("error", reject);
      socket.on("end", () => resolve(body));
      socket.write("GET / HTTP/1.1\r\nHost: review.invalid\r\nConnection: close\r\n\r\n");
    });
    request.end();
  });
}

export async function verifyRuntime(core, applyOverride, directory) {
  let child;
  let directHits = 0;
  let upstreamHits = 0;
  let logs = "";
  const target = http.createServer((request, response) => {
    directHits++;
    response.setHeader("Connection", "close");
    response.end("direct-target-reached");
  });
  const upstream = net.createServer((socket) => {
    upstreamHits++;
    socket.destroy();
  });
  try {
    const targetPort = await listen(target);
    const upstreamPort = await listen(upstream);
    const apiPort = await unusedPort();
    const mixedPort = await unusedPort();
    const node = (name) => ({ name, type: "socks5", server: "127.0.0.1", port: upstreamPort, udp: true });
    const nodesFile = join(directory, "runtime-nodes.yaml");
    writeFileSync(nodesFile, JSON.stringify({ proxies: [node("DIRECT"), node("Z-file"), node("Drop")] }));
    const profile = {
      proxies: [node("Z-local"), node("A-local")],
      "proxy-providers": {
        OpenAI: { type: "file", path: nodesFile, "exclude-filter": "^Drop$" },
        "节点选择": {
          type: "inline", payload: [node("Raw")],
          override: { "proxy-name": [{ pattern: "^Raw$", target: "DIRECT" }] },
        },
        "anx-direct-last": {
          type: "inline", payload: [node("RE")],
          override: { "additional-prefix": "DI", "additional-suffix": "CT" },
        },
        "anx-source-1": {
          type: "inline", payload: [node("Raw-expr")], override: { "override-expr": ['.name = "DIRECT"'] },
        },
      },
    };
    const config = applyOverride(profile);
    Object.assign(config, {
      mode: "rule", "log-level": "info", "mixed-port": mixedPort,
      "bind-address": "127.0.0.1", "external-controller": `127.0.0.1:${apiPort}`,
      dns: { enable: false }, tun: { enable: false }, profile: { "store-selected": false },
      hosts: { "review.invalid": "127.0.0.1" },
      rules: ["DOMAIN,review.invalid,节点选择", "MATCH,REJECT"],
    });
    const configFile = join(directory, "runtime.yaml");
    writeFileSync(configFile, JSON.stringify(config));
    child = spawn(core, ["-d", directory, "-f", configFile], { stdio: ["ignore", "pipe", "pipe"] });
    const collect = (chunk) => { logs = (logs + chunk).slice(-16000); };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    await once(child, "spawn");

    const groupPath = `/proxies/${encodeURIComponent("节点选择")}`;
    const renamedDirect = "订阅 · DIRECT";
    const expected = ["Z-local", "A-local", renamedDirect, "Z-file",
      renamedDirect, renamedDirect, renamedDirect, "DIRECT"];
    await waitForGroup(child, apiPort, groupPath, expected);
    assert.equal(config["proxy-groups"][0].use.length, 5);
    await api(apiPort, groupPath, "PUT", { name: "DIRECT" });
    assert.match(await requestThroughProxy(mixedPort, targetPort), /direct-target-reached/);
    assert.equal(directHits, 1);
    assert.equal(upstreamHits, 0, "DIRECT must never dial a subscription proxy");

    writeFileSync(nodesFile, JSON.stringify({ proxies: [node("Added"), node("DIRECT"), node("Z-file")] }));
    const firstProvider = config["proxy-groups"][0].use[0];
    await api(apiPort, `/providers/proxies/${encodeURIComponent(firstProvider)}`, "PUT");
    expected.splice(2, 0, "Added");
    assert.deepEqual((await api(apiPort, groupPath)).all, expected);
    assert.match(await requestThroughProxy(mixedPort, targetPort), /direct-target-reached/);
    assert.equal(directHits, 2);
    assert.equal(upstreamHits, 0, "DIRECT must remain direct after a provider update");
    console.log("runtime: order, provider aliases, final-name guard, real DIRECT, and provider update passed");
  } catch (error) {
    throw new Error(`${error.message}\n${logs}`, { cause: error });
  } finally {
    if (child?.pid && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGKILL");
      await exited;
    }
    await close(upstream);
    await close(target);
  }
}
