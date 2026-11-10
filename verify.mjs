import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { createContext, runInContext } from "node:vm";

const core = process.argv[2];
if (!core) throw new Error("Usage: node verify.mjs /path/to/mihomo");
const source = readFileSync(new URL("./dist/AkiraNyx-Clash-Party.js", import.meta.url), "utf8");
const tempRoot = realpathSync(tmpdir());
const directory = mkdtempSync(join(tempRoot, "akiranyx-mihomo-"));
const proxy = { name: "测试节点", type: "socks5", server: "127.0.0.1", port: 1080, udp: true };
const oldProvider = { type: "inline", behavior: "domain", payload: ["old.example"] };
const subscriptionProfile = {
  proxies: [proxy],
  "proxy-groups": [
    { name: "🔰 选择节点", type: "select", proxies: ["Youtube"] },
    { name: "节点选择", type: "select", proxies: ["🔰 选择节点", proxy.name] },
    { name: "Youtube", type: "select", proxies: ["DIRECT"] },
  ],
  "rule-providers": { "old-provider": oldProvider },
  rules: ["DOMAIN,old.example,REJECT", "MATCH,DIRECT"],
  dns: { enable: false, nameserver: ["127.0.0.53"] },
};
const providerProfile = {
  "proxy-providers": { demo: { type: "file", path: "./nodes.yaml" } },
};

function evaluate(script, profile) {
  const context = createContext({ console });
  return JSON.parse(runInContext(
    `${script}\nJSON.stringify(main(${JSON.stringify(profile)}))`, context, { timeout: 30000 },
  ));
}

function validate(config, name) {
  const file = join(directory, `${name}.yaml`);
  writeFileSync(file, JSON.stringify({ mode: "rule", ...config }), "utf8");
  const result = spawnSync(core, ["-t", "-d", directory, "-f", file], {
    encoding: "utf8", timeout: 60000,
  });
  if (result.status !== 0) {
    throw new Error(`${name}: ${result.error ?? ""}\n${result.stdout}\n${result.stderr}`);
  }
  console.log(`${name}: Mihomo validation passed`);
}

try {
  writeFileSync(join(directory, "nodes.yaml"), JSON.stringify({ proxies: [proxy] }), "utf8");
  const config = evaluate(source, subscriptionProfile);
  const groups = Object.fromEntries(config["proxy-groups"].map((group) => [group.name, group]));
  const providers = config["rule-providers"];
  assert.equal(config["proxy-groups"][0].name, "节点选择");
  for (const group of config["proxy-groups"]) {
    assert.match(group.icon, /^data:image\/svg\+xml,/);
  }
  assert.ok(decodeURIComponent(groups["节点选择"].icon).includes(">🚀</text>"));
  assert.equal(groups["🔰 选择节点"], undefined);
  assert.equal(groups["节点选择"].type, "select");
  assert.equal(groups["节点选择"]["include-all"], true);
  assert.equal(groups["节点选择"].proxies, undefined);
  assert.deepEqual(config.proxies, subscriptionProfile.proxies);
  assert.equal(config["proxy-groups"].filter(({ name }) => name === "Youtube").length, 1);
  assert.deepEqual(groups.Youtube.proxies, ["节点选择", "DIRECT"]);
  assert.deepEqual(groups.BiliBili.proxies, ["DIRECT", "BiliBili 港澳台"]);
  assert.deepEqual(groups["广告拦截"].proxies, ["REJECT", "PASS"]);
  assert.deepEqual(groups["QUIC 控制"].proxies, ["PASS", "REJECT"]);
  assert.deepEqual(groups["UDP 控制"].proxies, ["REJECT"]);
  assert.equal(groups["UDP 控制"]["default-selected"], "REJECT");
  assert.deepEqual(groups["Steam 下载"].proxies, ["DIRECT"]);
  assert.equal(groups.Telegram["default-selected"], "节点选择");
  assert.equal(groups.DeepSeek["default-selected"], "DIRECT");
  assert.deepEqual(providers["old-provider"], oldProvider);
  assert.ok(providers["anx-steam-download"].payload.includes("+.steamcontent.com"));
  assert.ok(providers["anx-steam-web"].payload.includes("+.steamcommunity.com"));
  assert.ok(providers["anx-bili-intl"].payload.includes("+.bilibili.tv"));
  assert.ok(providers["anx-telegram-ip"].payload.every((entry) => !entry.includes(":")));
  assert.equal(config.rules[0], "IP-CIDR6,::/0,REJECT,no-resolve");
  assert.ok(config.rules.includes("IP-CIDR,172.172.255.20/32,DIRECT,no-resolve"));
  assert.ok(!config.rules.some((rule) => rule.includes("old.example")));
  assert.deepEqual(config.rules.filter((rule) => rule.startsWith("MATCH,")), ["MATCH,节点选择"]);
  assert.deepEqual(config.rules.slice(-2), ["MATCH,节点选择", "NETWORK,UDP,UDP 控制"]);
  const order = ["anx-ads", "QUIC 控制", "anx-bili-intl", "anx-bilibili",
    "anx-steam-download", "anx-steam-web", "anx-domains-foreign", "anx-domains-cn",
    "anx-ip-foreign", "anx-ip-cn"];
  const positions = order.map((item) => config.rules.findIndex((rule) => rule.includes(item)));
  assert.ok(positions.every((position, i) => position >= 0 && (!i || position > positions[i - 1])));
  assert.equal(config.dns.enable, true);
  assert.equal(config.dns.ipv6, false);
  assert.ok(config.dns.nameserver.every((item) => item.endsWith("#节点选择")));
  assert.ok(config.dns["proxy-server-nameserver"].every((item) => !item.includes("#节点选择")));
  const dnsKeys = Object.keys(config.dns["nameserver-policy"]);
  assert.ok(dnsKeys.indexOf("rule-set:anx-domains-foreign") < dnsKeys.indexOf("rule-set:anx-domains-cn"));
  validate(config, "subscription-groups-replaced");

  const providerOnly = evaluate(source, providerProfile);
  assert.equal(providerOnly["proxy-groups"][0].name, "节点选择");
  assert.equal(providerOnly["proxy-groups"].find(({ name }) => name === "节点选择")["include-all"], true);
  assert.deepEqual(providerOnly["proxy-providers"], providerProfile["proxy-providers"]);
  validate(providerOnly, "provider-only");

  const guard = evaluate(source.replace("enableDnsGuard: false", "enableDnsGuard: true")
    .replace("allowedDnsIPv4: []", 'allowedDnsIPv4: ["192.168.1.53/32"]')
    .replace("localDnsPolicy: {}", 'localDnsPolicy: { "example.lan": "192.168.1.53" }'), {
    proxies: [proxy],
  });
  assert.equal(guard.rules[2], "DST-PORT,53/853,REJECT");
  assert.deepEqual(Object.keys(guard.dns["nameserver-policy"]).slice(0, 2), ["example.lan", "localhost"]);
  validate(guard, "dns-guard");
} finally {
  const resolved = realpathSync(directory);
  if (dirname(resolved) === tempRoot && basename(resolved).startsWith("akiranyx-mihomo-")) {
    rmSync(resolved, { recursive: true, force: true });
  }
}
