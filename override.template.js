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
const directProviderName = "anx-direct-last";
const directNameGuard = '.name |= sub("^DIRECT$"; "订阅 · DIRECT")';
const domesticGroups = new Set([
  "DeepSeek", "其他国内 AI", "BiliBili", "其他国内流媒体",
  "Steam 下载", "米哈游国内", "鹰角网络", "腾讯系软件服务",
]);
const groupEmoji = {
  "节点选择": "🚀",
  "广告拦截": "🛑",
  "QUIC 控制": "⚡",
  "UDP 控制": "🛡️",
  "OpenAI": "💬",
  "Anthropic": "🤖",
  "DeepSeek": "🐋",
  "微软 Copilot": "💡",
  "GitHub Copilot": "💻",
  "Gemini": "✨",
  "Apple Intelligence": "🪄",
  "其他国内 AI": "🧠",
  "其他国外 AI": "🌐",
  "Telegram": "✈️",
  "Youtube": "▶️",
  "Netflix": "🎬",
  "BiliBili": "📺",
  "BiliBili 港澳台": "🎞️",
  "其他国内流媒体": "🎵",
  "其他国外流媒体": "🍿",
  "Steam 下载": "📥",
  "Steam 商店和社区": "🛒",
  "米哈游国内": "🎮",
  "Hoyoverse 国外": "🌌",
  "鹰角网络": "🦅",
  "微软软件服务": "🪟",
  "微软系统服务": "⚙️",
  "谷歌软件服务": "🔍",
  "谷歌系统服务": "🧩",
  "Apple 软件服务": "🍎",
  "Apple 系统服务": "🛠️",
  "腾讯系软件服务": "🐧",
};

function selector(name, proxies) {
  return {
    name,
    type: "select",
    proxies,
    "default-selected": proxies[0],
  };
}

function prepareProxyProviders(inputProviders, groupNames) {
  const providers = new Map();
  const directProvider = { type: "inline", payload: [{ name: "DIRECT", type: "direct" }] };
  const reservedNames = new Set([...groupNames, directProviderName, "GLOBAL", "default"]);
  const usedNames = new Set([...reservedNames, ...Object.keys(inputProviders)]);
  let aliasIndex = 1;
  for (const [name, provider] of Object.entries(inputProviders)) {
    if (name === directProviderName && JSON.stringify(provider) === JSON.stringify(directProvider)) {
      continue;
    }
    let providerName = name;
    if (reservedNames.has(name)) {
      do {
        providerName = `anx-source-${aliasIndex++}`;
      } while (usedNames.has(providerName));
    }
    usedNames.add(providerName);

    const override = provider.override ?? {};
    const expressions = override["override-expr"] ?? [];
    if (!Array.isArray(expressions)) {
      throw new Error(`代理集合 ${name} 的 override-expr 必须是数组`);
    }
    // Runs after every upstream rename, including prefix/suffix and override-expr.
    const guardedExpressions = expressions[expressions.length - 1] === directNameGuard
      ? expressions : [...expressions, directNameGuard];
    providers.set(providerName, {
      ...provider, override: { ...override, "override-expr": guardedExpressions },
    });
  }
  const sourceProviderNames = [...providers.keys()];
  if (sourceProviderNames.length) providers.set(directProviderName, directProvider);
  return { proxyProviders: Object.fromEntries(providers), sourceProviderNames };
}

function validateGroupReferences(groups) {
  const visiting = new Set();
  const visited = new Set();
  function visit(name) {
    if (visited.has(name) || !groups.has(name)) return;
    if (visiting.has(name)) throw new Error(`代理组循环引用：${name}`);
    visiting.add(name);
    for (const child of groups.get(name).proxies ?? []) visit(child);
    visiting.delete(name);
    visited.add(name);
  }
  for (const name of groups.keys()) visit(name);
}

function withGroupIcon(group) {
  if (!Object.hasOwn(groupEmoji, group.name)) return group;
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
    + '<text x="12" y="12" text-anchor="middle" dominant-baseline="central" font-size="18" '
    + `font-family="Segoe UI Emoji, Apple Color Emoji, Noto Color Emoji, sans-serif">${groupEmoji[group.name]}</text></svg>`;
  return { ...group, icon: `data:image/svg+xml,${encodeURIComponent(svg)}` };
}

function buildGroups(config, services, rules) {
  const nodeNames = new Set((config.proxies ?? []).map((proxy) => proxy.name));
  const managedGroupNames = new Set(services.map(([, group]) => group));
  managedGroupNames.delete("DIRECT");
  managedGroupNames.add(primaryGroup);
  managedGroupNames.add("QUIC 控制");
  managedGroupNames.add("UDP 控制");
  managedGroupNames.add("BiliBili 港澳台");
  for (const name of managedGroupNames) {
    if (nodeNames.has(name)) {
      throw new Error(`代理节点名称与覆写代理组冲突：${name}`);
    }
  }
  const { proxyProviders, sourceProviderNames } = prepareProxyProviders(
    config["proxy-providers"] ?? {}, managedGroupNames,
  );

  const groups = new Map();
  const primary = { name: primaryGroup, type: "select", proxies: [...nodeNames] };
  if (sourceProviderNames.length) {
    // Provider members follow explicit proxies; a final inline provider keeps DIRECT last.
    primary.use = [...sourceProviderNames, directProviderName];
  } else {
    primary.proxies.push("DIRECT");
  }
  groups.set(primaryGroup, primary);
  for (const name of managedGroupNames) {
    if (name === primaryGroup) continue;
    const candidates = domesticGroups.has(name) ? ["DIRECT", primaryGroup] : [primaryGroup, "DIRECT"];
    groups.set(name, { ...selector(name, [...candidates, ...nodeNames]), use: sourceProviderNames });
  }
  groups.set("广告拦截", selector("广告拦截", ["REJECT", "PASS"]));
  groups.set("QUIC 控制", selector("QUIC 控制", ["PASS", "REJECT"]));
  groups.set("UDP 控制", selector("UDP 控制", ["REJECT"]));
  groups.set("Steam 下载", selector("Steam 下载", ["DIRECT"]));
  groups.set("BiliBili", selector("BiliBili", ["DIRECT", "BiliBili 港澳台"]));
  groups.set("BiliBili 港澳台", {
    ...selector("BiliBili 港澳台", [primaryGroup, ...nodeNames]), use: sourceProviderNames,
  });

  validateGroupReferences(groups);
  const order = new Set([primaryGroup]);
  for (const rule of rules) {
    const name = rule.replace(/,no-resolve$/, "").split(",").pop();
    if (groups.has(name)) order.add(name);
    if (name === "BiliBili") order.add("BiliBili 港澳台");
  }
  return { groups: [...order].map((name) => withGroupIcon(groups.get(name))), proxyProviders };
}

function domainMatch(names) {
  if (names.length === 1) return `RULE-SET,${names[0]}`;
  return `OR,(${names.map((name) => `(RULE-SET,${name})`).join(",")})`;
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
    let match = domainMatch(names);
    if (policy === "Apple 系统服务") {
      // Apple Music/TV hosts also fall under the broader iTunes system domains.
      const [software] = services.find(([providers]) => providers.includes("anx-apple-software"));
      match = `AND,((${match}),(NOT,((${domainMatch(software)}))))`;
    }
    rules.push(`${match},${policy}`);
    if (policy === "广告拦截") rules.push("AND,((NETWORK,UDP),(DST-PORT,443)),QUIC 控制");
    if (policy === "Telegram") rules.push("RULE-SET,anx-telegram-ip,Telegram,no-resolve");
  }
  rules.push(
    "RULE-SET,anx-ip-foreign,节点选择,no-resolve",
    "RULE-SET,anx-ip-cn,DIRECT,no-resolve",
    "MATCH,节点选择",
    // 选中的节点不支持 UDP 时，内核会跳过上面的 MATCH。
    "NETWORK,UDP,UDP 控制",
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
  const { providers: ruleProviders, services, bootstrap } = buildData;
  const existingRuleProviders = config["rule-providers"] ?? {};
  for (const [name, provider] of Object.entries(ruleProviders)) {
    if (Object.hasOwn(existingRuleProviders, name)
        && JSON.stringify(existingRuleProviders[name]) !== JSON.stringify(provider)) {
      throw new Error(`订阅规则集名称与覆写冲突：${name}`);
    }
  }
  const rules = buildRules(services);
  const { groups, proxyProviders } = buildGroups(config, services, rules);
  const dns = buildDns(services, bootstrap);
  config["proxy-groups"] = groups;
  if (config["proxy-providers"] || Object.keys(proxyProviders).length) {
    config["proxy-providers"] = proxyProviders;
  }
  config["rule-providers"] = { ...existingRuleProviders, ...ruleProviders };
  config.rules = rules;
  config.dns = dns;
  return config;
}
