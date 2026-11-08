// AkiraNyx Clash Party 覆写。使用订阅提供的节点。
const options = {
  // 需要能在代理启动前直连，保留 TLS 证书校验。
  bootstrapDoH: null,
  // 示例：{ "+.campus.example": "192.168.1.53" }。仅填写明确授权的内部域名与解析器。
  localDnsPolicy: {},
  // DNS 接管验证通过后再开启。允许直连的 DNS 地址填 IPv4 CIDR。
  enableDnsGuard: false,
  allowedDnsIPv4: [],
};

const buildData = /* BUILD_DATA */ null;
const primaryGroup = "节点选择";
const domesticGroups = new Set([
  "DeepSeek", "其他国内 AI", "BiliBili", "其他国内流媒体",
  "Steam 下载", "米哈游国内", "鹰角网络",
]);

function selector(name, proxies, includeAll = false) {
  return {
    name,
    type: "select",
    proxies,
    "default-selected": proxies[0],
    ...(includeAll ? { "include-all": true } : {}),
  };
}

function mergeGroups(config, services) {
  const original = config["proxy-groups"] ?? [];
  const groups = new Map(original.map((group) => [group.name, group]));
  const nodeNames = new Set((config.proxies ?? []).map((proxy) => proxy.name));
  const managed = new Set(services.map(([, group]) => group));
  managed.delete("DIRECT");
  managed.delete(primaryGroup);
  managed.add("QUIC 控制");
  managed.add("BiliBili 港澳台");
  for (const name of [...managed, primaryGroup]) {
    if (nodeNames.has(name)) {
      throw new Error(`代理节点名称与覆写代理组冲突：${name}`);
    }
  }

  for (const name of managed) {
    const candidates = domesticGroups.has(name) ? ["DIRECT", primaryGroup] : [primaryGroup, "DIRECT"];
    groups.set(name, selector(name, candidates, true));
  }
  groups.set("广告拦截", selector("广告拦截", ["REJECT", "PASS"]));
  groups.set("QUIC 控制", selector("QUIC 控制", ["PASS", "REJECT"]));
  groups.set("Steam 下载", selector("Steam 下载", ["DIRECT"]));
  groups.set("BiliBili", selector("BiliBili", ["DIRECT", "BiliBili 港澳台"]));
  groups.set("BiliBili 港澳台", selector("BiliBili 港澳台", [primaryGroup], true));

  const primary = groups.get(primaryGroup);
  const reachesPrimary = (name, seen) => {
    if (name === primaryGroup) return true;
    if (seen.has(name)) return false;
    seen.add(name);
    return (groups.get(name)?.proxies ?? []).some((child) => reachesPrimary(child, seen));
  };
  if (!primary) {
    groups.set(primaryGroup, { name: primaryGroup, type: "select", "include-all": true });
  } else {
    const safeCandidates = (primary.proxies ?? []).filter(
      (name) => !reachesPrimary(name, new Set()),
    );
    if (safeCandidates.length !== (primary.proxies ?? []).length) {
      const kept = { ...primary, proxies: safeCandidates };
      if (!safeCandidates.length && !kept.use?.length && !kept["include-all"]
          && !kept["include-all-proxies"] && !kept["include-all-providers"]) {
        groups.set(primaryGroup, { name: primaryGroup, type: "select", "include-all": true });
      } else {
        groups.set(primaryGroup, kept);
      }
    }
  }

  const visiting = new Set();
  const visited = new Set();
  function check(name) {
    if (visited.has(name) || !groups.has(name)) return;
    if (visiting.has(name)) throw new Error(`代理组循环引用：${name}`);
    visiting.add(name);
    for (const child of groups.get(name).proxies ?? []) check(child);
    visiting.delete(name);
    visited.add(name);
  }
  for (const name of groups.keys()) check(name);
  const primaryConfig = groups.get(primaryGroup);
  groups.delete(primaryGroup);
  return [primaryConfig, ...groups.values()];
}

function domainRule(names, policy) {
  if (names.length === 1) return `RULE-SET,${names[0]},${policy}`;
  return `OR,(${names.map((name) => `(RULE-SET,${name})`).join(",")}),${policy}`;
}

function buildRules(services) {
  const rules = ["IP-CIDR6,::/0,REJECT,no-resolve"];
  if (options.enableDnsGuard) {
    for (const cidr of options.allowedDnsIPv4) {
      if (!/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(cidr)) {
        throw new Error(`DNS 白名单必须填写 IPv4 CIDR：${cidr}`);
      }
      rules.push(`AND,((DST-PORT,53/853),(IP-CIDR,${cidr},no-resolve)),DIRECT`);
    }
    rules.push("DST-PORT,53/853,REJECT");
  }
  rules.push(
    "IP-CIDR,172.172.255.20/32,DIRECT,no-resolve",
    "DOMAIN,localhost,DIRECT",
    "DOMAIN-SUFFIX,lan,DIRECT",
    "DOMAIN-SUFFIX,local,DIRECT",
    "DOMAIN-SUFFIX,home.arpa,DIRECT",
    ...["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
      "169.254.0.0/16", "224.0.0.0/4"].map((cidr) => `IP-CIDR,${cidr},DIRECT,no-resolve`),
  );
  for (const [names, policy] of services) {
    rules.push(domainRule(names, policy));
    if (policy === "广告拦截") rules.push("AND,((NETWORK,UDP),(DST-PORT,443)),QUIC 控制");
    if (policy === "Telegram") rules.push("RULE-SET,anx-telegram-ip,Telegram,no-resolve");
  }
  rules.push(
    "RULE-SET,anx-ip-foreign,节点选择,no-resolve",
    "RULE-SET,anx-ip-cn,DIRECT,no-resolve",
    "MATCH,节点选择",
  );
  return rules;
}

function buildDns(services, bootstrap) {
  const bootstrapDoH = options.bootstrapDoH ?? bootstrap;
  if (!/^https:\/\/\d{1,3}(?:\.\d{1,3}){3}\/[^#]+$/.test(bootstrapDoH)) {
    throw new Error("引导 DoH 必须使用以 IPv4 地址接入的 HTTPS URL");
  }
  const overseas = [
    "https://cloudflare-dns.com/dns-query#节点选择",
    "https://dns.google/dns-query#节点选择",
  ];
  const domestic = [bootstrapDoH, "https://doh.pub/dns-query"];
  const localNames = ["localhost", "+.lan", "+.local", "+.home.arpa"];
  const nameserverPolicy = { ...options.localDnsPolicy };
  for (const name of localNames) nameserverPolicy[name] ??= "rcode://success";
  for (const [names, , dnsClass] of services) {
    if (dnsClass) {
      for (const name of names) {
        nameserverPolicy[`rule-set:${name}`] = dnsClass === "cn" ? domestic : overseas;
      }
    }
  }
  return {
    enable: true,
    ipv6: false,
    "prefer-h3": false,
    "respect-rules": false,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": [
      ...localNames, ...Object.keys(options.localDnsPolicy),
      "+.msftconnecttest.com", "+.msftncsi.com",
    ],
    "default-nameserver": [bootstrapDoH],
    "proxy-server-nameserver": [bootstrapDoH],
    "nameserver-policy": nameserverPolicy,
    nameserver: overseas,
  };
}

function main(config) {
  if (!config || typeof config !== "object" || !buildData) {
    throw new Error("缺少订阅配置或内联数据，请使用构建后的覆写文件");
  }
  const { providers, services, bootstrap } = buildData;
  const previousProviders = config["rule-providers"] ?? {};
  for (const [name, provider] of Object.entries(providers)) {
    if (Object.hasOwn(previousProviders, name)
        && JSON.stringify(previousProviders[name]) !== JSON.stringify(provider)) {
      throw new Error(`订阅规则集名称与覆写冲突：${name}`);
    }
  }
  config["proxy-groups"] = mergeGroups(config, services);
  config["rule-providers"] = { ...previousProviders, ...providers };
  config.rules = buildRules(services);
  config.dns = buildDns(services, bootstrap);
  return config;
}
