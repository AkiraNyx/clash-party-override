"""Build the self-contained Clash Party override from MetaCubeX data."""

import argparse
import hashlib
import json
import re
from ipaddress import IPv4Address, IPv4Network, summarize_address_range
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "dist" / "AkiraNyx-Clash-Party.js"
GEO_URLS = (
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/release/",
    "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/",
)
TELEGRAM_CIDRS = "https://core.telegram.org/resources/cidr.txt"

# Ordered from dedicated services to broad categories. DNS follows the same domain order.
# Each entry is (provider name, policy, DNS class, GeoSite labels, extra domains).
# In extra domains, "+." means domain and subdomains. Other entries are exact.
SERVICES = [
    ("ads", "广告拦截", None, "category-ads-all", ()),
    ("openai", "OpenAI", "foreign", "openai", ()),
    ("anthropic", "Anthropic", "foreign", "anthropic", ()),
    ("deepseek", "DeepSeek", "cn", "deepseek", ()),
    ("copilot", "微软 Copilot", "foreign", "", (
        "+.copilot.com", "+.copilot.microsoft.com", "+.copilot.cloud.microsoft",
        "+.copilot-stg.com",
    )),
    ("github-copilot", "GitHub Copilot", "foreign", "github-copilot", ()),
    ("gemini", "Gemini", "foreign", "google-gemini", ()),
    ("apple-ai", "Apple Intelligence", "foreign", "apple-intelligence", (
        "cp4.cloudflare.com",
    )),
    ("telegram", "Telegram", "foreign", "telegram", ()),
    ("youtube", "Youtube", "foreign", "youtube", ()),
    ("netflix", "Netflix", "foreign", "netflix", ()),
    ("bili-intl", "其他国外流媒体", "foreign", "biliintl", ()),
    ("iqiyi-intl", "其他国外流媒体", "foreign", "", ("+.iq.com",)),
    ("bilibili", "BiliBili", "cn", "bilibili bilibili-cdn", ()),
    ("steam-download", "Steam 下载", "cn", "", (
        "+.steamcontent.com", "steampipe.akamaized.net", "steampipe-kr.akamaized.net",
        "client-update.queniuqe.com", "dl.steam.clngaa.com", "st.dl.bscstorage.net",
        "st.dl.eccdnx.com", "st.dl.pinyuncloud.com", "lv.queniujq.cn",
        "xz.pphimalayanrt.com",
    )),
    ("steam-web", "Steam 商店和社区", "foreign", "", (
        "+.steampowered.com", "+.steamcommunity.com", "+.steamstatic.com",
        "+.steamusercontent.com", "+.steam-chat.com", "+.s.team",
        "steamstore-a.akamaihd.net", "steamcommunity-a.akamaihd.net",
        "steamcommunity-a.akamaihd.net.edgesuite.net", "steamuserimages-a.akamaihd.net",
        "steamusercontent-a.akamaihd.net", "steamcdn-a.akamaihd.net",
    )),
    ("mihoyo-cn", "米哈游国内", "cn", "mihoyo-cn", ()),
    ("hoyoverse", "Hoyoverse 国外", "foreign", "hoyoverse", ()),
    ("hypergryph", "鹰角网络", "cn", "", (
        "+.hypergryph.com", "+.hycdn.cn", "+.gryphline.com",
    )),
    ("microsoft-system", "微软系统服务", "foreign", "", (
        "+.windowsupdate.com", "+.update.microsoft.com", "+.delivery.mp.microsoft.com",
        "+.dl.delivery.mp.microsoft.com", "+.do.dsp.mp.microsoft.com",
        "+.msftconnecttest.com", "+.msftncsi.com", "activation.sls.microsoft.com",
        "licensing.mp.microsoft.com", "displaycatalog.mp.microsoft.com",
        "purchase.mp.microsoft.com", "storecatalogrevocation.storequality.microsoft.com",
    )),
    ("google-system", "谷歌系统服务", "foreign", "google-play googlefcm", (
        "update.googleapis.com", "tools.google.com", "dl.google.com",
    )),
    ("apple-software", "Apple 软件服务", "foreign", "icloud apple-music apple-tvplus", ()),
    ("apple-system", "Apple 系统服务", "foreign", "apple-update itunes", (
        "+.apps.apple.com", "+.push.apple.com",
    )),
    ("other-ai-cn", "其他国内 AI", "cn", "category-ai-cn", ()),
    ("other-ai-foreign", "其他国外 AI", "foreign", "category-ai-!cn", ()),
    ("media-cn", "其他国内流媒体", "cn", "iqiyi youku douyin douyu huya tencent-tme", (
        "+.mgtv.com", "v.qq.com", "video.qq.com", "+.music.163.com", "+.music.126.net",
    )),
    ("media-foreign", "其他国外流媒体", "foreign",
        "primevideo spotify hulu twitch dazn bahamut tiktok", (
            "+.disneyplus.com", "+.disneypluscdn.com", "+.dssott.com",
            "+.max.com", "+.hbomax.com", "+.hbomaxcdn.com",
        )),
    ("microsoft", "微软软件服务", "foreign", "microsoft github onedrive azure xbox", ()),
    ("google", "谷歌软件服务", "foreign", "google", ()),
    ("apple", "Apple 软件服务", "foreign", "apple", ()),
    ("domains-foreign", "节点选择", "foreign", "geolocation-!cn", ()),
    ("domains-cn", "DIRECT", "cn", "cn", ()),
]

# Exclude non-public IPv4 space even if the upstream country labels change.
SPECIAL_IPV4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/29", "192.0.0.8/32",
    "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)


def download(urls):
    failures = []
    for url in urls:
        try:
            with urlopen(Request(url, headers={"User-Agent": "AkiraNyx-Overwrite/1.0"}), timeout=45) as response:
                return response.read()
        except OSError as error:
            failures.append(f"{url}: {error}")
    raise RuntimeError("\n".join(failures))


def varint(data, position):
    value = 0
    for shift in range(0, 70, 7):
        byte = data[position]
        position += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, position
    raise ValueError("Invalid protobuf varint")


def fields(data):
    data = memoryview(data)
    position = 0
    while position < len(data):
        tag, position = varint(data, position)
        wire_type = tag & 7
        if wire_type == 0:
            value, position = varint(data, position)
        elif wire_type == 2:
            size, position = varint(data, position)
            end = position + size
            if end > len(data):
                raise ValueError("Truncated protobuf record")
            value = data[position:end]
            position = end
        else:
            raise ValueError(f"Unexpected protobuf wire type {wire_type}")
        yield tag >> 3, value


def records(data):
    for field, entry in fields(data):
        if field != 1:
            raise ValueError("Unexpected Geo data record")
        items = list(fields(entry))
        if not items or items[0][0] != 1:
            raise ValueError("Missing Geo data label")
        yield bytes(items[0][1]).decode().upper(), [value for key, value in items if key == 2]


def geosite_entries(data, wanted):
    result = {}
    for label, entries in records(data):
        label = label.lower()
        if label in wanted:
            if label in result or not entries:
                raise ValueError(f"Empty or duplicate GeoSite category: {label}")
            result[label] = []
            for entry in entries:
                entry = dict(fields(entry))
                kind = entry.get(1, 0)
                value = bytes(entry[2]).decode()
                if kind not in (0, 1, 2, 3) or not value or any(char in value for char in "\r\n"):
                    raise ValueError(f"Unsupported GeoSite entry in {label}")
                result[label].append((kind, value))
    if wanted - result.keys():
        raise ValueError(f"Missing GeoSite categories: {sorted(wanted - result.keys())}")
    if len(result["cn"]) < 50000 or len(result["geolocation-!cn"]) < 10000:
        raise ValueError("GeoSite appears truncated or is the lite dataset")
    return result


def ip_interval(network):
    network = IPv4Network(network)
    return int(network.network_address), int(network.broadcast_address)


def merge_intervals(intervals):
    result = []
    for start, end in sorted(intervals):
        if result and start <= result[-1][1] + 1:
            result[-1] = (result[-1][0], max(end, result[-1][1]))
        else:
            result.append((start, end))
    return result


def subtract_intervals(intervals, exclusions):
    result = []
    index = 0
    for start, end in intervals:
        while index < len(exclusions) and exclusions[index][1] < start:
            index += 1
        while index < len(exclusions) and exclusions[index][0] <= end:
            excluded_start, excluded_end = exclusions[index]
            if start < excluded_start:
                result.append((start, excluded_start - 1))
            if excluded_end >= end:
                start = end + 1
                break
            start = excluded_end + 1
            index += 1
        if start <= end:
            result.append((start, end))
    return result


def country_ranges(data):
    china, other = [], []
    reserved = [ip_interval(value) for value in SPECIAL_IPV4]
    countries = set()
    for label, entries in records(data):
        if label not in {"PRIVATE"} and not re.fullmatch("[A-Z]{2}", label):
            continue
        if label in {"AP", "EU", "UN", "XX", "ZZ"}:
            continue
        countries.add(label)
        target = reserved if label == "PRIVATE" else china if label == "CN" else other
        for entry in entries:
            entry = dict(fields(entry))
            address = entry[1]
            if len(address) != 4:
                continue
            prefix = entry.get(2, 0)
            if not 1 <= prefix <= 32:
                raise ValueError(f"Invalid public IPv4 prefix in {label}: {prefix}")
            start = int.from_bytes(address, "big")
            size = 1 << (32 - prefix)
            if start % size:
                raise ValueError(f"Noncanonical GeoIP range in {label}")
            target.append((start, start + size - 1))
    if len(countries) < 150 or len(china) < 1000 or len(other) < 100000:
        raise ValueError("GeoIP appears truncated or is the lite dataset")

    reserved = merge_intervals(reserved)
    china = subtract_intervals(merge_intervals(china), reserved)
    foreign = subtract_intervals(merge_intervals(other), merge_intervals([*reserved, *china]))
    if not china or not foreign or subtract_intervals(foreign, china) != foreign:
        raise ValueError("Public IPv4 sets are empty or overlap")

    def cidrs(intervals):
        return [str(network) for start, end in intervals
                for network in summarize_address_range(IPv4Address(start), IPv4Address(end))]

    return cidrs(china), cidrs(foreign)


def provider(behavior, payload):
    if not payload:
        raise ValueError(f"Empty {behavior} provider")
    return {"type": "inline", "behavior": behavior, "payload": payload}


def domain_providers(geo):
    result, ordered = {}, []
    for name, policy, dns, labels, extras in SERVICES:
        simple, classical = set(), set()
        for label in labels.split():
            for kind, value in geo[label]:
                if kind in (2, 3) and not any(char in value for char in "+*"):
                    simple.add(("+." if kind == 2 else "") + value.lower())
                else:
                    rule_type = ("DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-SUFFIX", "DOMAIN")[kind]
                    classical.add(f"{rule_type},{value}")
        simple.update(extras)
        names = []
        if simple:
            names.append(f"anx-{name}")
            result[names[-1]] = provider("domain", sorted(simple))
        if classical:
            names.append(f"anx-{name}-patterns")
            result[names[-1]] = provider("classical", sorted(classical))
        if not names:
            raise ValueError(f"Empty domain service: {name}")
        ordered.append([names, policy, dns])
    return result, ordered


def build(site, geoip, telegram, bootstrap):
    wanted = {label for _, _, _, labels, _ in SERVICES for label in labels.split()}
    providers, services = domain_providers(geosite_entries(site, wanted))
    china, foreign = country_ranges(geoip)
    networks = [line for line in telegram.decode().splitlines() if line.strip()]
    telegram_ipv4 = [str(IPv4Network(network)) for network in networks if ":" not in network]
    if len(telegram_ipv4) < 5:
        raise ValueError("Telegram IPv4 list appears truncated")
    providers["anx-telegram-ip"] = provider("ipcidr", telegram_ipv4)
    providers["anx-ip-foreign"] = provider("ipcidr", foreign)
    providers["anx-ip-cn"] = provider("ipcidr", china)
    sources = {name: hashlib.sha256(data).hexdigest() for name, data in (
        ("geosite.dat", site), ("geoip.dat", geoip), ("telegram-cidr.txt", telegram)
    )}
    return {"providers": providers, "services": services, "sources": sources, "bootstrap": bootstrap}


def main():
    assert subtract_intervals([(1, 20)], [(2, 5), (8, 10), (15, 25)]) == [
        (1, 1), (6, 7), (11, 14)
    ]
    assert merge_intervals([(4, 9), (1, 3), (12, 13)]) == [(1, 9), (12, 13)]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--geosite", type=Path)
    parser.add_argument("--geoip", type=Path)
    parser.add_argument("--telegram", type=Path)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--bootstrap", default="https://223.5.5.5/dns-query")
    args = parser.parse_args()

    def geo_file(path, name):
        return path.read_bytes() if path else download([url + name for url in GEO_URLS])

    telegram = args.telegram.read_bytes() if args.telegram else download([TELEGRAM_CIDRS])
    data = build(geo_file(args.geosite, "geosite.dat"), geo_file(args.geoip, "geoip.dat"),
                 telegram, args.bootstrap)
    encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    source = (ROOT / "override.template.js").read_text(encoding="utf-8")
    if source.count("/* BUILD_DATA */ null") != 1:
        raise ValueError("Invalid override template")
    result = source.replace("/* BUILD_DATA */ null", encoded)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(".js.tmp")
    temporary.write_text(result, encoding="utf-8", newline="\n")
    temporary.replace(args.output)
    print(f"{args.output} ({len(result.encode()):,} bytes)")


if __name__ == "__main__":
    main()
