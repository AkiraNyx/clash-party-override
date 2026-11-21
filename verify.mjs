import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { createContext, runInContext } from "node:vm";
import { verifyRuntime } from "./verify-runtime.mjs";

const core = process.argv[2];
if (!core) throw new Error("Usage: node verify.mjs /path/to/mihomo");
const source = readFileSync(new URL("./dist/AkiraNyx-Clash-Party.js", import.meta.url), "utf8");
const tempRoot = realpathSync(tmpdir());
const directory = mkdtempSync(join(tempRoot, "akiranyx-mihomo-"));
const proxy = { name: "测试节点", type: "socks5", server: "127.0.0.1", port: 1080, udp: true };
const orderedProxies = [{ ...proxy, name: "Z-node" }, proxy, { ...proxy, name: "A-node" }];
const nodeNames = orderedProxies.map(({ name }) => name);
const oldProvider = { type: "inline", behavior: "domain", payload: ["old.example"] };
const subscriptionProfile = {
  proxies: orderedProxies,
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
  "proxy-providers": {
    "Z-provider": { type: "file", path: "./nodes.yaml" },
    "A-provider": { type: "inline", payload: [{ ...proxy, name: "provider-node" }] },
  },
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
  const groupNames = config["proxy-groups"].map(({ name }) => name);
  assert.deepEqual(groupNames, [
    "节点选择", "广告拦截", "QUIC 控制", "OpenAI", "Anthropic", "DeepSeek",
    "微软 Copilot", "GitHub Copilot", "Gemini", "Apple Intelligence",
    "其他国内 AI", "其他国外 AI", "Telegram", "Youtube", "Netflix",
    "其他国外流媒体", "BiliBili", "BiliBili 港澳台", "其他国内流媒体",
    "Steam 下载", "Steam 商店和社区", "米哈游国内", "Hoyoverse 国外", "鹰角网络",
    "微软系统服务", "谷歌系统服务", "Apple 系统服务",
    "微软软件服务", "谷歌软件服务", "Apple 软件服务", "腾讯系软件服务", "UDP 控制",
  ]);
  const routedGroups = config.rules.map((rule) => rule.split(",").filter((item) => item !== "no-resolve").at(-1))
    .filter((name) => groups[name] && name !== "节点选择")
    .filter((name, i, names) => !i || name !== names[i - 1]);
  assert.deepEqual(routedGroups, groupNames.filter((name) => !["节点选择", "BiliBili 港澳台"].includes(name)));
  for (const group of config["proxy-groups"]) {
    assert.match(group.icon, /^data:image\/svg\+xml,/);
  }
  assert.ok(decodeURIComponent(groups["节点选择"].icon).includes(">🚀</text>"));
  assert.equal(groups["🔰 选择节点"], undefined);
  assert.equal(groups["节点选择"].type, "select");
  assert.equal(groups["节点选择"]["include-all"], undefined);
  assert.deepEqual(groups["节点选择"].proxies, [...nodeNames, "DIRECT"]);
  assert.deepEqual(config.proxies, subscriptionProfile.proxies);
  assert.equal(config["proxy-groups"].filter(({ name }) => name === "Youtube").length, 1);
  assert.deepEqual(groups.Youtube.proxies, ["节点选择", "DIRECT", ...nodeNames]);
  assert.deepEqual(groups.BiliBili.proxies, ["DIRECT", "BiliBili 港澳台"]);
  assert.deepEqual(groups["广告拦截"].proxies, ["REJECT", "PASS"]);
  assert.deepEqual(groups["QUIC 控制"].proxies, ["PASS", "REJECT"]);
  assert.deepEqual(groups["UDP 控制"].proxies, ["REJECT"]);
  assert.equal(groups["UDP 控制"]["default-selected"], "REJECT");
  assert.deepEqual(groups["Steam 下载"].proxies, ["DIRECT"]);
  assert.equal(groups.Telegram["default-selected"], "节点选择");
  assert.equal(groups.DeepSeek["default-selected"], "DIRECT");
  assert.equal(groups["腾讯系软件服务"]["default-selected"], "DIRECT");
  assert.deepEqual(groups["腾讯系软件服务"].proxies, ["DIRECT", "节点选择", ...nodeNames]);
  assert.equal(groups["腾讯系软件服务"]["include-all"], undefined);
  assert.deepEqual(providers["old-provider"], oldProvider);
  for (const host of ["anthropic.com.cdn.cloudflare.net", "anthropic.auth0.com",
    "anthropic-com.ghost.io", "browser-intake-us5-datadoghq.com"]) {
    assert.ok(providers["anx-anthropic"].payload.includes(host));
    assert.ok(!providers["anx-anthropic"].payload.includes(`+.${host}`));
  }
  assert.ok(config.rules.includes("RULE-SET,anx-anthropic,Anthropic"));
  assert.ok(providers["anx-steam-download"].payload.includes("+.steamcontent.com"));
  assert.ok(providers["anx-steam-web"].payload.includes("+.steamcommunity.com"));
  assert.ok(providers["anx-bili-intl"].payload.includes("+.bilibili.tv"));
  for (const domain of ["+.qq.com", "+.weixin.com", "+.qcloud.com", "+.tencent.com"]) {
    assert.ok(providers["anx-tencent"].payload.includes(domain));
  }
  const appleSystemRule = config.rules.find((rule) => rule.endsWith(",Apple 系统服务"));
  assert.match(appleSystemRule, /^AND,/);
  assert.ok(appleSystemRule.includes("RULE-SET,anx-apple-system"));
  assert.match(appleSystemRule, /\(NOT,\(\(.*RULE-SET,anx-apple-software/);
  assert.ok(providers["anx-telegram-ip"].payload.every((entry) => !entry.includes(":")));
  assert.equal(config.rules[0], "IP-CIDR6,::/0,REJECT,no-resolve");
  assert.ok(config.rules.includes("IP-CIDR,172.172.255.20/32,DIRECT,no-resolve"));
  assert.ok(!config.rules.some((rule) => rule.includes("old.example")));
  assert.deepEqual(config.rules.filter((rule) => rule.startsWith("MATCH,")), ["MATCH,节点选择"]);
  assert.deepEqual(config.rules.slice(-2), ["MATCH,节点选择", "NETWORK,UDP,UDP 控制"]);
  const order = ["anx-ads", "QUIC 控制", "anx-other-ai-cn", "anx-other-ai-foreign",
    "anx-bili-intl", "anx-iqiyi-intl", "anx-media-foreign", "anx-bilibili", "anx-media-cn",
    "anx-steam-download", "anx-steam-web", "anx-tencent", "anx-domains-foreign", "anx-domains-cn",
    "anx-ip-foreign", "anx-ip-cn"];
  const positions = order.map((item) => config.rules.findIndex((rule) => rule.includes(item)));
  assert.ok(positions.every((position, i) => position >= 0 && (!i || position > positions[i - 1])));
  assert.equal(config.dns.enable, true);
  assert.equal(config.dns.ipv6, false);
  assert.ok(config.dns.nameserver.every((item) => item.endsWith("#节点选择")));
  assert.deepEqual(config.dns["nameserver-policy"]["rule-set:anx-anthropic"], config.dns.nameserver);
  assert.deepEqual(config.dns["nameserver-policy"]["rule-set:anx-tencent"],
    config.dns["nameserver-policy"]["rule-set:anx-domains-cn"]);
  assert.ok(config.dns["proxy-server-nameserver"].every((item) => !item.includes("#节点选择")));
  const dnsKeys = Object.keys(config.dns["nameserver-policy"]);
  for (const name of ["anx-other-ai-cn", "anx-media-cn"]) {
    assert.ok(dnsKeys.indexOf(`rule-set:${name}`) < dnsKeys.indexOf("rule-set:anx-tencent"));
  }
  assert.ok(dnsKeys.indexOf("rule-set:anx-domains-foreign") < dnsKeys.indexOf("rule-set:anx-domains-cn"));
  validate(config, "subscription-groups-replaced");

  const proxiesOnly = evaluate(source, { proxies: orderedProxies });
  assert.deepEqual(proxiesOnly["proxy-groups"][0].proxies, [...nodeNames, "DIRECT"]);
  assert.deepEqual(proxiesOnly.proxies, orderedProxies);
  validate(proxiesOnly, "proxies-only");

  const providerOnly = evaluate(source, providerProfile);
  assert.equal(providerOnly["proxy-groups"][0].name, "节点选择");
  assert.equal(providerOnly["proxy-groups"][0]["include-all"], undefined);
  assert.deepEqual(providerOnly["proxy-groups"][0].proxies, []);
  assert.deepEqual(providerOnly["proxy-groups"][0].use, ["Z-provider", "A-provider", "anx-direct-last"]);
  for (const [name, provider] of Object.entries(providerProfile["proxy-providers"])) {
    const { override, ...definition } = providerOnly["proxy-providers"][name];
    assert.deepEqual(definition, provider);
    assert.equal(override["override-expr"].length, 1);
  }
  assert.deepEqual(providerOnly["proxy-providers"]["anx-direct-last"], {
    type: "inline", payload: [{ name: "DIRECT", type: "direct" }],
  });
  for (const group of providerOnly["proxy-groups"].slice(1)) {
    assert.ok(!group.use?.includes("anx-direct-last"));
  }
  validate(providerOnly, "provider-only");

  const mixed = evaluate(source, { ...providerProfile, proxies: orderedProxies });
  assert.deepEqual(mixed["proxy-groups"][0].proxies, nodeNames);
  assert.deepEqual(mixed["proxy-groups"][0].use, ["Z-provider", "A-provider", "anx-direct-last"]);
  validate(mixed, "proxies-and-providers");
  const reapplied = evaluate(source, mixed);
  assert.deepEqual(reapplied["proxy-groups"], mixed["proxy-groups"]);
  assert.deepEqual(reapplied["proxy-providers"], mixed["proxy-providers"]);
  const collisions = evaluate(source, {
    "proxy-providers": {
      OpenAI: { type: "file", path: "./nodes.yaml" },
      "节点选择": { type: "file", path: "./nodes.yaml" },
      "anx-direct-last": { type: "file", path: "./nodes.yaml" },
      "anx-source-1": { type: "file", path: "./nodes.yaml" },
    },
  });
  const collisionProviders = collisions["proxy-groups"][0].use;
  assert.equal(new Set(collisionProviders).size, 5);
  assert.equal(collisionProviders[3], "anx-source-1");
  assert.equal(collisionProviders[4], "anx-direct-last");
  assert.ok(collisionProviders.slice(0, 3).every((name) => !["OpenAI", "节点选择", "anx-direct-last"].includes(name)));
  validate(collisions, "provider-name-collisions");
  assert.deepEqual(evaluate(source, collisions), collisions);
  assert.throws(() => evaluate(source, {
    "proxy-providers": {
      Invalid: { type: "inline", payload: [proxy], override: { "override-expr": '.name = "DIRECT"' } },
    },
  }), /override-expr 必须是数组/);

  const guard = evaluate(source.replace("enableDnsGuard: false", "enableDnsGuard: true")
    .replace("allowedDnsIPv4: []", 'allowedDnsIPv4: ["192.168.1.53/32"]')
    .replace("localDnsPolicy: {}", 'localDnsPolicy: { "example.lan": "192.168.1.53" }'), {
    proxies: [proxy],
  });
  assert.equal(guard.rules[2], "DST-PORT,53/853,REJECT");
  assert.deepEqual(Object.keys(guard.dns["nameserver-policy"]).slice(0, 2), ["example.lan", "localhost"]);
  validate(guard, "dns-guard");
  await verifyRuntime(core, (profile) => evaluate(source, profile), directory);
} finally {
  const resolved = realpathSync(directory);
  if (dirname(resolved) === tempRoot && basename(resolved).startsWith("akiranyx-mihomo-")) {
    rmSync(resolved, { recursive: true, force: true });
  }
}
