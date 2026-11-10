# AkiraNyx Clash Party 覆写

## 导入

1. 在 Clash Party 的「覆写」页导入 `dist/AkiraNyx-Clash-Party.js`。在目标订阅的「编辑信息」中选用该覆写，代理模式选「规则」。
2. 本覆写会替换订阅自带的代理组和分流规则。关闭会与它冲突的额外规则编辑或其他覆写，并关闭客户端内置的「DNS 覆写」。在运行时配置确认 `rules` 和 `dns` 生效。
3. 国外 DoH 使用 `节点选择`。首次启用前，确认该组选中可用的代理节点，并验证代理尚未连接时，引导 DoH 能直连。初始候选为 `https://223.5.5.5/dns-query`，可用文件开头的 `bootstrapDoH` 替换为经验证的 IPv4 HTTPS DNS 端点。
4. B 站默认直连。先在 `BiliBili 港澳台` 手选适用节点，再把 `BiliBili` 切到该组。广告默认拦截，QUIC 默认继续分流。没有匹配到支持 UDP 的出口时，由 `UDP 控制` 拒绝剩余 UDP。

## DNS 与 IPv6 验收

- 仅当校园网或局域网确实需要解析内部域名时，在文件开头的 `localDnsPolicy` 明确写入域名与授权解析器。常见本地后缀有空应答兜底。校园网地址 `172.172.255.20/32` 直接使用 IPv4 规则。
- `enableDnsGuard` 默认关闭。确认 Windows DNS 接管、TUN 设置和浏览器安全 DNS 后再启用。若需直连本地 DNS，将它的 IPv4 CIDR 填进 `allowedDnsIPv4`。这项守卫拦截进入内核的 53、853 端口连接。
- 通过客户端设置关闭 IPv6，并测试 IPv6 拦截。浏览器侧限制 WebRTC 非代理 UDP，再用实际经过代理的浏览器验证 DNS 和 WebRTC。规则文件只控制进入 Mihomo 的连接。

## GitHub Actions

仓库的 `.github/workflows/build.yml` 负责构建和发布。工作流在默认分支每日运行，也可在 Actions 页面手动运行。仓库需允许该工作流提交生成文件。工作流仅在校验通过且文件有变化时提交产物。

在 Clash Party 用 [固定 Raw URL](https://raw.githubusercontent.com/AkiraNyx/clash-party-override/main/dist/AkiraNyx-Clash-Party.js) 导入远程覆写。Actions 发布新版后，在客户端点覆写卡片的刷新按钮拉取并热重载。

修改构建数据时编辑 `build.py`，修改覆写设置时编辑 `override.template.js`。在项目目录本地运行 `python build.py` 生成，再运行 `node verify.mjs /path/to/mihomo` 检查。生成的规则数据来自 [MetaCubeX](https://github.com/MetaCubeX/meta-rules-dat) 和 [Telegram](https://core.telegram.org/resources/cidr.txt)，文件内记录源数据 SHA-256。
