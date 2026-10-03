#!/usr/bin/env python3
# sub-proxy: pull the encrypted v2ray.vpn built-in subscription mirrors,
# base64-decode + AES-256-CBC decrypt (keys from V2ray VPN 6.5.0 APK),
# serve the plaintext subscription on :60088 for any V2Ray/Clash client.
import base64, hmac, ipaddress, json, os, socket, ssl, threading, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 60088
REFRESH = 900  # seconds between re-pulls
KEY = b"36KeAARKZuKF39N9LFyycLUyKMhZDq0B"
IV  = b"36KeAARKZuKF39N9"
UA  = "NekoBox/Android/6.5.0 (Prefer ClashMeta Format)"
# Access token: /, /cn, /en require ?token=<TOKEN> (or "Authorization: Bearer <TOKEN>").
# /healthz stays open for monitoring. Rotate via the SUB_PROXY_TOKEN env var.
TOKEN = os.environ.get("SUB_PROXY_TOKEN") or "CHANGE_ME_GENERATE_A_RANDOM_TOKEN"
BASE = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(BASE, "last_good.txt")

# UA markers that identify a Clash / Mihomo-family client (needs YAML).
# If the lowercased User-Agent contains any of these, serve mihomo YAML;
# otherwise serve raw vmess links (v2rayNG / NekoBox / SagerNet / Shadowrocket).
# A client can also force the format with ?clash / ?mihomo / ?yaml query params.
CLASH_UA_MARKERS = (
    "clash", "mihomo", "cfi", "hiddify", "streisand", "stagger", "flclash", "clashy",
)

MIRRORS = {
    "cn": [
        "https://gitlab.com/bobmolen/cloud/raw/master/vsp-cn.py",
        "https://bannedbook.github.io/fanqiang/vsp-cn.py",
        "https://raw.githubusercontent.com/bannedbook/fanqiang/master/docs/vsp-cn.py",
        "https://storage.googleapis.com/jwnews/vsp-cn.py",
    ],
    "en": [
        "https://bannedbook.github.io/fanqiang/vsp-en.py",
        "https://raw.githubusercontent.com/bannedbook/fanqiang/master/docs/vsp-en.py",
        "https://gitlab.com/bobmolen/cloud/raw/master/vsp-en.py",
        "https://storage.googleapis.com/jwnews/vsp-en.py",
    ],
}


class Cache:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {"cn": None, "en": None}
        self.dropped = {"cn": [], "en": []}  # domains dead at last refresh
        self.meta = {}
        self.last_error = None
        self.last_fetch = 0


_cache = Cache()

def _aes_decrypt(raw):
    # b64decode drops whitespace/invalid chars automatically
    ct = base64.b64decode("".join(raw.split()))
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
        pt = c.update(ct) + c.finalize()
    except ImportError:
        from Crypto.Cipher import AES
        pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
        pt = pt[:-pad]
    return pt.decode("utf-8", "replace")


def fetch_plain(lang):
    """Fetch mirrors in order; decrypt AES blob, or pass through if plaintext."""
    last = None
    for u in MIRRORS[lang]:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=20) as r:
                body = r.read().decode("utf-8", "replace")
            try:
                text = _aes_decrypt(body)
            except Exception:
                if "://" in body:
                    text = body.strip()  # upstream switched to plaintext
                else:
                    last = Exception("no usable content from %s" % u)
                    continue
            if "://" in text:
                return text
            last = Exception("decrypted result has no links (%s)" % u)
        except Exception as e:
            last = e
    raise last if last else Exception("all mirrors failed for " + lang)


# ---------------------------------------------------------------- geolocation
# Rename each vmess node to '<ip location>·<old name>' using the domain (add)
# inside the node: DNS-resolve the domain, geolocate the IP (ipwho.is, no key).
# All lookups are best-effort: on any failure the link is kept unchanged.
CC_ZH = {
    "US": "美国", "GB": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰", "SE": "瑞典",
    "DK": "丹麦", "CH": "瑞士", "IT": "意大利", "ES": "西班牙", "JP": "日本", "KR": "韩国",
    "SG": "新加坡", "HK": "香港", "TW": "台湾", "MO": "澳门", "CA": "加拿大", "AU": "澳大利亚",
    "NZ": "新西兰", "MY": "马来西亚", "TH": "泰国", "VN": "越南", "ID": "印度尼西亚",
    "PH": "菲律宾", "TR": "土耳其", "RU": "俄罗斯", "IN": "印度", "BR": "巴西",
    "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "CL": "智利", "PL": "波兰",
    "FI": "芬兰", "NO": "挪威", "AT": "奥地利", "BE": "比利时", "PT": "葡萄牙", "GR": "希腊",
}

_IP_GEO = {}   # ip -> location string (persistent; IPs are stable)
_DOM_GEO = {}  # domain -> location string (per-cycle; domains rotate)
_DOM_IP = {}   # domain -> resolved ipv4 (cache successes only)


def _resolve_ipv4(host):
    ip = _DOM_IP.get(host)
    if ip is not None:
        return ip
    try:
        ip = socket.getaddrinfo(host, 80, socket.AF_INET)[0][4][0]
        _DOM_IP[host] = ip
        return ip
    except Exception:
        return None


def _geo_ip(ip):
    loc = _IP_GEO.get(ip)
    if loc is not None:
        return loc
    try:
        req = urllib.request.Request("https://ipwho.is/%s" % ip,
                                     headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10) as r:
            j = json.load(r)
        cc = str(j.get("country_code") or "")
        country = CC_ZH.get(cc) or str(j.get("country") or "")
        city = str(j.get("city") or "").strip()
        loc = ("%s·%s" % (country, city)) if country and city else (country or city)
    except Exception:
        loc = ""
    _IP_GEO[ip] = loc
    return loc


def _geo_domain(host):
    loc = _DOM_GEO.get(host)
    if loc is not None:
        return loc
    ip = _resolve_ipv4(host)
    loc = _geo_ip(ip) if ip else ""
    _DOM_GEO[host] = loc
    return loc


def _geo_rename(text):
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if "vmess://" not in line:
            lines.append(line)
            continue
        payload = _vmess_payload(line)
        if payload is None:
            lines.append(line)
            continue
        try:
            j = json.loads(base64.b64decode(payload))
            host = str(j.get("add") or "")
            loc = _geo_domain(host) if host else ""
            if loc:
                old = str(j.get("ps") or "").strip()
                j["ps"] = ("%s·%s" % (loc, old)) if old else loc
                line = "vmess://" + base64.b64encode(
                    json.dumps(j, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
        except Exception:
            pass  # keep the original line untouched
        lines.append(line)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------- DNS liveness
# A node whose domain has no A record anywhere is unusable by every client
# (mihomo: "dns resolve failed: couldn't find ip").  At refresh time probe
# each vmess node's 'add' host via binary DoH; drop the node when NO
# provider returns an A record.  IP-literal nodes always pass.  The probe is
# repeated every refresh, so a dead domain that comes back to life is
# re-added automatically.  A control lookup (baidu.com) guards against a
# broken probe: if even the control fails, DoH itself is unreachable from
# this host and the filter is skipped for the whole cycle.

_DNS_CTX = ssl.create_default_context()
_DNS_CTX.check_hostname = False
_DNS_CTX.verify_mode = ssl.CERT_NONE
# JSON DoH /resolve endpoints, tried in order (Google + AliDNS + Cloudflare).
# JSON proved reachable under GFW interference where binary POST /dns-query
# gets flaky/blocked.  Status: 0 = NOERROR; NODATA is status 0 + empty
# Answer.  A record = type 1 with a non-empty data field.
_DNS_PROVIDERS = (
    "https://dns.google/resolve",
    "https://223.5.5.5/resolve",
    "https://1.1.1.1/resolve",
)
_DNS_CONTROL = "baidu.com"


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _vmess_add(line):
    """Lowercased 'add' host of a vmess:// line, or None (also for non-vmess)."""
    p = _vmess_payload(line)
    if not p:
        return None
    try:
        add = str(json.loads(base64.b64decode(p)).get("add") or "").lower()
    except Exception:
        return None
    return add or None


def _doh_lookup(host):
    """True when ANY JSON-DoH provider returns at least one A record."""
    for base in _DNS_PROVIDERS:
        try:
            url = "%s?name=%s&type=A" % (base, urllib.parse.quote(host))
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=5, context=_DNS_CTX) as r:
                d = json.loads(r.read())
            status = int(d.get("Status", d.get("status", 1)))
            if status != 0:
                continue
            for a in d.get("Answer") or d.get("answer") or []:
                t = int(a.get("Type", a.get("type", 0)))
                data = a.get("Data", a.get("data"))
                if t == 1 and data:
                    return True
        except Exception:
            continue
    return False


def filter_dead_domains(text):
    """Drop vmess nodes whose 'add' host resolves to nothing anywhere.

    Returns (filtered_text, [dead hosts]).  If the control lookup fails
    (DoH itself unreachable), returns the text untouched."""
    lines = [l.strip() for l in (text or "").splitlines() if l.strip()]
    hosts = set()
    for l in lines:
        add = _vmess_add(l)
        if add and not _is_ip(add):
            hosts.add(add)
    if not hosts:
        return text, []
    with ThreadPoolExecutor(max_workers=4) as pool:
        control = pool.submit(_doh_lookup, _DNS_CONTROL)
        ranked = sorted(hosts)
        res = list(pool.map(_doh_lookup, ranked))
        probe_ok = control.result()
    if not probe_ok:
        print("dns-filter: control probe failed, probe broken this cycle, "
              "keeping all nodes", flush=True)
        return text, []
    alive = dict(zip(ranked, res))
    dead = [h for h in ranked if not alive[h]]
    if not dead:
        return text, []
    out = [l for l in lines if _vmess_add(l) not in set(dead)]
    return "\n".join(out) + "\n", dead


def refresh(lang):
    text = _geo_rename(fetch_plain(lang))
    filtered, dead = filter_dead_domains(text)
    if dead:
        print("dns-filter: dropped %d dead domain(s): %s" % (len(dead), ", ".join(dead)), flush=True)
    with _cache.lock:
        _cache.data[lang] = filtered
        _cache.dropped[lang] = dead
        _cache.last_fetch = time.time()
        _cache.last_error = None
        if lang == "cn":
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                f.write(filtered)


def merged_data():
    """Deduped union of cn + en link lists. Locks exactly once (snapshot)."""
    with _cache.lock:
        cn = _cache.data.get("cn") or ""
        en = _cache.data.get("en") or ""
    seen = []
    for body in (cn, en):
        for line in body.splitlines():
            line = line.strip()
            if line and line not in seen:
                seen.append(line)
    return "\n".join(seen) + "\n" if seen else None


# ---------------------------------------------------------------- clash / mihomo
# Convert the vmess:// link list into an importable Mihomo (Clash Meta) YAML.
# net=httpupgrade is mapped to ws: v2ray servers that accept httpupgrade also
# accept the standard ws handshake, and ws works across old and new mihomo.

def _vmess_payload(line):
    """Return the base64 JSON payload of a vmess:// link, or None.

    Uses split on the scheme (not a fixed slice) so a BOM or stray leading
    junk before 'vmess://' cannot corrupt the payload.
    """
    if "vmess://" not in line:
        return None
    return line.split("vmess://", 1)[1].strip()


def _vmess_line_to_proxy(line, used_names, pin_ip=False):
    payload = _vmess_payload(line)
    if payload is None:
        return None
    try:
        j = json.loads(base64.b64decode(payload))
    except Exception:
        return None
    add = str(j.get("add") or "")
    if not add:
        return None
    name = str(j.get("ps") or "").strip() or add
    if name in used_names:  # mihomo rejects duplicate proxy names
        # fall back to the server host; last resort is a numbered suffix
        if add not in used_names and add != name:
            name = ("%s·%s" % (name, add)) if name else add
        else:
            name = "%s #%d" % (name, len(used_names) + 1)
    used_names.add(name)

    # IP-pinning: dial the resolved IP instead of the domain.  Cloudflare
    # routes by Host/SNI, so when pinning we must keep the original domain as
    # the Host header (ws/h2) and SNI (tls) — otherwise CF can't pick origin.
    server = add
    if pin_ip and not _is_ip(add):
        ip = _resolve_ipv4(add)
        if ip:
            server = ip

    p = {
        "name": name,
        "type": "vmess",
        "server": server,
        "port": int(j.get("port") or 0),
        "uuid": str(j.get("id") or ""),
        "alterId": int(j.get("aid") or 0),
        "cipher": str(j.get("scy") or "auto"),
        "tls": str(j.get("tls") or "") in ("1", "true", "tls"),
        "skip-cert-verify": True,
        "udp": True,
    }
    if pin_ip and server != add and p["tls"]:
        p["servername"] = add  # SNI must stay the domain when TLS is on

    net = str(j.get("net") or "tcp").lower()
    path = str(j.get("path") or "").strip()
    host = str(j.get("host") or "").strip()
    # Host header to send: prefer the link's own 'host' field, else the
    # original domain only when we pinned the IP (so CF still routes right).
    host_header = host or (add if (pin_ip and server != add) else "")
    if net in ("ws", "websocket", "httpupgrade"):
        p["network"] = "ws"
        opts = {}
        if net == "httpupgrade":
            # v2ray's httpupgrade transport: mihomo stays on network ws but
            # must switch the handshake to HTTP Upgrade (Meta-Docs
            # transport.md: ws-opts.v2ray-http-upgrade).  fast-open is kept
            # false to match v2ray's default (fastOpen=false) so mihomo waits
            # for the 101 response before sending vmess data.
            opts["v2ray-http-upgrade"] = True
            opts["v2ray-http-upgrade-fast-open"] = False
        if path:
            opts["path"] = path
        if host_header:
            opts["headers"] = {"Host": host_header}
        if opts:
            p["ws-opts"] = opts
    elif net in ("h2", "http2", "http", "https"):
        p["network"] = "h2"
        opts = {}
        if path:
            opts["path"] = path
        if host_header:
            opts["headers"] = {"Host": host_header}
        if opts:
            p["http-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        if path:
            p["grpc-opts"] = {"grpc-service-name": path}
        if host_header:
            p["grpc-opts"] = {"grpc-service-name": path,
                              "grpc-host": host_header}
    else:
        p["network"] = "tcp"
    return p


def _yaml_scalar(v):
    # JSON string escaping is valid double-quoted YAML; emit scalars that way.
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return json.dumps(str(v), ensure_ascii=False)


def clash_yaml(body, pin_ip=False):
    """Build a full Mihomo (Clash Meta) YAML profile from vmess:// link lines."""
    proxies = []
    used = set()
    for line in (body or "").splitlines():
        line = line.strip()
        if "vmess://" in line:
            px = _vmess_line_to_proxy(line, used, pin_ip=pin_ip)
            if px:
                proxies.append(px)
        # non-vmess lines are skipped: mihomo needs a structured def per protocol.

    out = []
    out.append("# Mihomo (Clash Meta) profile generated by sub-proxy")
    out.append("# source: v2ray.vpn built-in subscription (AES-decrypted)")
    out.append("# nodes: %d" % len(proxies))
    out.append("mixed-port: 7890")
    out.append("allow-lan: false")
    out.append("mode: rule")
    out.append("log-level: info")
    out.append("external-controller: 127.0.0.1:9090")
    out.append("unified-delay: true")
    out.append("tcp-concurrent: true")
    out.append("dns:")
    out.append("  enable: true")
    out.append("  ipv6: false")
    out.append("  enhanced-mode: fake-ip")
    out.append('  fake-ip-range: "198.18.0.1/16"')
    out.append("  use-hosts: true")
    out.append("  respect-rules: true")
    out.append("  default-nameserver:")
    out.append("    - 223.5.5.5")
    out.append("    - 119.29.29.29")
    out.append("  nameserver:")
    out.append("    - 223.5.5.5")
    out.append("    - 119.29.29.29")
    out.append('    - "https://223.5.5.5/dns-query"')
    out.append('    - "https://120.53.53.53/dns-query"')
    out.append('    - "https://dns.alidns.com/dns-query"')
    out.append('    - "https://doh.pub/dns-query"')
    out.append("  proxy-server-nameserver:")
    out.append("    - 223.5.5.5")
    out.append("    - 119.29.29.29")
    out.append("    - 114.114.114.114")
    out.append('    - "https://223.5.5.5/dns-query"')
    out.append('    - "https://120.53.53.53/dns-query"')
    out.append('    - "https://dns.alidns.com/dns-query"')
    out.append('    - "https://doh.pub/dns-query"')
    out.append("  fake-ip-filter:")
    for f in ("*.lan", "*.local", "*.localdomain", "*.example", "*.invalid",
              "*.localhost", "*.test", "*.internal", "*.priv",
              "lens.l.google.com", "*.msftconnecttest.com", "*.msftncsi.com"):
        out.append('    - "%s"' % f)
    if not proxies:
        out.append("proxies: []")
    else:
        out.append("proxies:")
        for p in proxies:
            prefix = "  - "
            for k, v in p.items():
                if isinstance(v, dict):
                    out.append("%s%s:" % (prefix, k))
                    for k2, v2 in v.items():
                        if isinstance(v2, dict):
                            out.append("      %s:" % k2)
                            for k3, v3 in v2.items():
                                out.append("        %s: %s" % (k3, _yaml_scalar(v3)))
                        else:
                            out.append("      %s: %s" % (k2, _yaml_scalar(v2)))
                else:
                    out.append("%s%s: %s" % (prefix, k, _yaml_scalar(v)))
                prefix = "    "
        names = [_yaml_scalar(p["name"]) for p in proxies]
        out.append("proxy-groups:")
        out.append('  - name: "PROXY"')
        out.append("    type: select")
        out.append("    proxies:")
        for n in names:
            out.append("      - %s" % n)
        out.append("      - DIRECT")
        out.append('  - name: "AUTO"')
        out.append("    type: url-test")
        out.append("    proxies:")
        for n in names:
            out.append("      - %s" % n)
        out.append('    url: "http://www.google.com"')
        out.append("    interval: 300")
        out.append("    tolerance: 50")
        out.append("rules:")
        # ── Private & loopback ──
        out.append("  - DOMAIN,127.0.0.1,DIRECT")
        out.append("  - DOMAIN-SUFFIX,local,DIRECT")
        out.append("  - DOMAIN-SUFFIX,localhost,DIRECT")
        out.append("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
        out.append("  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve")
        out.append("  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
        out.append("  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")
        out.append("  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve")
        out.append("  - IP-CIDR,198.18.0.0/16,DIRECT,no-resolve")
        out.append("  - IP-CIDR,224.0.0.0/4,DIRECT,no-resolve")
        out.append("  - IP-CIDR6,::1/128,DIRECT,no-resolve")
        out.append("  - IP-CIDR6,fc00::/7,DIRECT,no-resolve")
        out.append("  - IP-CIDR6,fe80::/10,DIRECT,no-resolve")
        # ── Ad / tracker ──
        out.append("  - DOMAIN-KEYWORD,admarvel,REJECT")
        out.append("  - DOMAIN-KEYWORD,admaster,REJECT")
        out.append("  - DOMAIN-KEYWORD,adsage,REJECT")
        out.append("  - DOMAIN-KEYWORD,adsmogo,REJECT")
        out.append("  - DOMAIN-KEYWORD,adsrvmedia,REJECT")
        out.append("  - DOMAIN-KEYWORD,adwords,REJECT")
        out.append("  - DOMAIN-KEYWORD,adservice,REJECT")
        out.append("  - DOMAIN-SUFFIX,appsflyer.com,REJECT")
        out.append("  - DOMAIN-KEYWORD,domob,REJECT")
        out.append("  - DOMAIN-SUFFIX,doubleclick.net,REJECT")
        out.append("  - DOMAIN-KEYWORD,duomeng,REJECT")
        out.append("  - DOMAIN-KEYWORD,dwtrack,REJECT")
        out.append("  - DOMAIN-KEYWORD,guanggao,REJECT")
        out.append("  - DOMAIN-KEYWORD,lianmeng,REJECT")
        out.append("  - DOMAIN-SUFFIX,mmstat.com,REJECT")
        out.append("  - DOMAIN-KEYWORD,mopub,REJECT")
        out.append("  - DOMAIN-KEYWORD,omgmta,REJECT")
        out.append("  - DOMAIN-KEYWORD,openx,REJECT")
        out.append("  - DOMAIN-KEYWORD,partnerad,REJECT")
        out.append("  - DOMAIN-KEYWORD,pingfore,REJECT")
        out.append("  - DOMAIN-KEYWORD,supersonicads,REJECT")
        out.append("  - DOMAIN-KEYWORD,uedas,REJECT")
        out.append("  - DOMAIN-KEYWORD,umeng,REJECT")
        out.append("  - DOMAIN-KEYWORD,usage,REJECT")
        out.append("  - DOMAIN-SUFFIX,vungle.com,REJECT")
        out.append("  - DOMAIN-KEYWORD,wlmonitor,REJECT")
        out.append("  - DOMAIN-KEYWORD,zjtoolbar,REJECT")
        # ── Apple push / services ──
        out.append("  - DOMAIN,developer.apple.com,AUTO")
        out.append("  - DOMAIN,testflight.apple.com,AUTO")
        out.append("  - DOMAIN,sandbox.itunes.apple.com,AUTO")
        out.append("  - DOMAIN,itunes.apple.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,apps.apple.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,blobstore.apple.com,AUTO")
        out.append("  - DOMAIN,cvws.icloud-content.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,apple-dns.net,AUTO")
        out.append("  - DOMAIN,ocsp.apple.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,digicert.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,services.googleapis.cn,AUTO")
        out.append("  - IP-CIDR,1.1.1.1/32,AUTO,no-resolve")
        out.append("  - IP-CIDR,8.8.8.8/32,AUTO,no-resolve")
        # ── Domestic CDN / China-direct ──
        out.append("  - DOMAIN,cn.bing.com,DIRECT")
        out.append("  - DOMAIN,safebrowsing.urlsec.qq.com,DIRECT")
        out.append("  - DOMAIN,safebrowsing.googleapis.com,DIRECT")
        out.append("  - DOMAIN-KEYWORD,baidu,DIRECT")
        out.append("  - DOMAIN-KEYWORD,alibaba,DIRECT")
        out.append("  - DOMAIN-KEYWORD,alicdn,DIRECT")
        out.append("  - DOMAIN-KEYWORD,alipay,DIRECT")
        out.append("  - DOMAIN-KEYWORD,taobao,DIRECT")
        out.append("  - DOMAIN-KEYWORD,tencent,DIRECT")
        out.append("  - DOMAIN-KEYWORD,bilibili,DIRECT")
        out.append("  - DOMAIN-KEYWORD,xiaomi,DIRECT")
        out.append("  - DOMAIN-KEYWORD,officecdn,DIRECT")
        out.append("  - DOMAIN-SUFFIX,apple.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,icloud.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,mzstatic.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,microsoft.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,office.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,office365.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,microsoftonline.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qq.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,weixin.qq.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,wx.qq.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qlogo.cn,DIRECT")
        out.append("  - DOMAIN-SUFFIX,gtimg.cn,DIRECT")
        out.append("  - DOMAIN-SUFFIX,servicewechat.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,wechatpay.cn,DIRECT")
        out.append("  - DOMAIN-SUFFIX,tencent-cloud.net,DIRECT")
        out.append("  - DOMAIN-SUFFIX,tencent.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,tenpay.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,126.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,126.net,DIRECT")
        out.append("  - DOMAIN-SUFFIX,127.net,DIRECT")
        out.append("  - DOMAIN-SUFFIX,163.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,360buyimg.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,36kr.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,acfun.tv,DIRECT")
        out.append("  - DOMAIN-SUFFIX,aixifan.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,amap.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,autonavi.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,bdimg.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,bdstatic.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,bilibili.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,bilivideo.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,caiyunapp.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,clouddn.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,csdn.net,DIRECT")
        out.append("  - DOMAIN-SUFFIX,ctrip.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,dianping.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,douban.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,doubanio.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,duokan.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,ele.me,DIRECT")
        out.append("  - DOMAIN-SUFFIX,iciba.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,ifeng.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,ifengimg.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,ipip.net,DIRECT")
        out.append("  - DOMAIN-SUFFIX,iqiyi.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,jd.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,jianshu.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,le.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,lecloud.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,meituan.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,meituan.net,DIRECT")
        out.append("  - DOMAIN-SUFFIX,mi.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,miaopai.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,miui.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,miwifi.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,netease.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,oschina.net,DIRECT")
        out.append("  - DOMAIN-SUFFIX,pstatp.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qcloud.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qdaily.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qhimg.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qhres.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qidian.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qihucdn.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qiniu.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qiniucdn.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qiyipic.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,qqurl.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,segmentfault.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,smzdm.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,sogou.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,sogoucdn.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,sohu.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,soku.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,speedtest.net,DIRECT")
        out.append("  - DOMAIN-SUFFIX,sspai.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,suning.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,taobao.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,tianyancha.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,tmall.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,tudou.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,umetrip.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,upaiyun.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,upyun.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,veryzhun.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,weibo.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,xiami.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,xiami.net,DIRECT")
        out.append("  - DOMAIN-SUFFIX,xiaomicp.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,ximalaya.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,xmcdn.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,xunlei.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,yhd.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,yihaodianimg.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,yinxiang.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,ykimg.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,youdao.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,youku.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,zealer.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,zhihu.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,zhimg.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,zoho.com,DIRECT")
        out.append("  - DOMAIN-SUFFIX,cn,DIRECT")
        out.append("  - DOMAIN-KEYWORD,-cn,DIRECT")
        # ── Global services ──
        out.append("  - DOMAIN-KEYWORD,google,AUTO")
        out.append("  - DOMAIN-KEYWORD,gmail,AUTO")
        out.append("  - DOMAIN-KEYWORD,youtube,AUTO")
        out.append("  - DOMAIN-KEYWORD,facebook,AUTO")
        out.append("  - DOMAIN-SUFFIX,fb.me,AUTO")
        out.append("  - DOMAIN-SUFFIX,fbcdn.net,AUTO")
        out.append("  - DOMAIN-KEYWORD,twitter,AUTO")
        out.append("  - DOMAIN-SUFFIX,twimg.com,AUTO")
        out.append("  - DOMAIN-KEYWORD,instagram,AUTO")
        out.append("  - DOMAIN-KEYWORD,github,AUTO")
        out.append("  - DOMAIN-KEYWORD,openai,AUTO")
        out.append("  - DOMAIN-KEYWORD,anthropic,AUTO")
        out.append("  - DOMAIN-KEYWORD,telegram,AUTO")
        out.append("  - DOMAIN-SUFFIX,telegram.org,AUTO")
        out.append("  - DOMAIN-SUFFIX,telegra.ph,AUTO")
        out.append("  - DOMAIN-KEYWORD,whatsapp,AUTO")
        out.append("  - DOMAIN-KEYWORD,netflix,AUTO")
        out.append("  - DOMAIN-KEYWORD,spotify,AUTO")
        out.append("  - DOMAIN-KEYWORD,dropbox,AUTO")
        out.append("  - DOMAIN-KEYWORD,blogspot,AUTO")
        out.append("  - DOMAIN-KEYWORD,amazon,AUTO")
        out.append("  - DOMAIN-SUFFIX,v2ex.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,medium.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,reddit.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,pixiv.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,cloudflare.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,cloudfront.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,t.me,AUTO")
        out.append("  - DOMAIN-SUFFIX,ytimg.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,youtu.be,AUTO")
        out.append("  - DOMAIN-SUFFIX,gstatic.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,ggpht.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,google.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,google.com.hk,AUTO")
        out.append("  - DOMAIN-SUFFIX,googleapis.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,gvt0.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,appspot.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,android.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,chromium.org,AUTO")
        out.append("  - DOMAIN-SUFFIX,golang.org,AUTO")
        out.append("  - DOMAIN-SUFFIX,angularjs.org,AUTO")
        out.append("  - DOMAIN-SUFFIX,wikipedia.org,AUTO")
        out.append("  - DOMAIN-SUFFIX,wikipedia.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,wikimedia.org,AUTO")
        out.append("  - DOMAIN-SUFFIX,wikileaks.org,AUTO")
        out.append("  - DOMAIN-SUFFIX,duckduckgo.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,archive.org,AUTO")
        out.append("  - DOMAIN-SUFFIX,sourceforge.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,stackoverflow.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,soundcloud.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,vimeo.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,vimeocdn.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,twitch.tv,AUTO")
        out.append("  - DOMAIN-SUFFIX,jtvnw.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,docker.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,fastly.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,akamaized.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,edgecastcdn.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,edgekey.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,edgesuite.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,llnwd.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,cachefly.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,azureedge.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,azurewebsites.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,awsstatic.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,ampproject.org,AUTO")
        out.append("  - DOMAIN-SUFFIX,gravatar.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,gmodules.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,tinypic.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,tumblr.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,tumblr.co,AUTO")
        out.append("  - DOMAIN-SUFFIX,txmblr.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,blogger.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,blogspot.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,blogspot.hk,AUTO")
        out.append("  - DOMAIN-SUFFIX,wordpress.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,wp.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,disqus.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,disquscdn.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,feedly.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,feedburner.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,flipboard.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,onedrive.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,onenote.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,live.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,live.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,livefilestore.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,outlook.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,hotmail.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,sfx.ms,AUTO")
        out.append("  - DOMAIN-SUFFIX,gfx.ms,AUTO")
        out.append("  - DOMAIN-SUFFIX,windows.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,windows.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,msedge.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,nsstatic.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,adobe.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,macromedia.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,typekit.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,linkedin.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,licdn.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,pinterest.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,techcrunch.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,theverge.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,engadget.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,nytimes.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,nyt.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,bloomberg.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,wsj.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,wsj.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,time.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,timeinc.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,cnn.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,bbc.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,bbc.co.uk,AUTO")
        out.append("  - DOMAIN-SUFFIX,sky.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,imgur.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,flickr.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,staticflickr.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,line-apps.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,yahoo.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,yimg.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,aolcdn.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,bing.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,skype.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,box.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,box.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,evernote.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,trello.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,slack.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,slack-edge.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,zoom.us,AUTO")
        out.append("  - DOMAIN-SUFFIX,zoom.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,dribbble.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,ubnt.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,vultr.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,linode.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,digitalocean.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,openvpn.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,nssurge.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,apkpure.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,name.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,godaddy.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,globalsign.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,comodoca.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,entrust.net,AUTO")
        out.append("  - DOMAIN-SUFFIX,usertrust.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,symcb.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,symcd.com,AUTO")
        out.append("  - DOMAIN-SUFFIX,trustasiassl.com,AUTO")
        # ── Telegram IP ranges ──
        out.append("  - IP-CIDR,91.108.4.0/22,AUTO,no-resolve")
        out.append("  - IP-CIDR,91.108.8.0/22,AUTO,no-resolve")
        out.append("  - IP-CIDR,91.108.16.0/22,AUTO,no-resolve")
        out.append("  - IP-CIDR,91.108.56.0/22,AUTO,no-resolve")
        out.append("  - IP-CIDR,149.154.160.0/20,AUTO,no-resolve")
        out.append("  - IP-CIDR6,2001:67c:4e8::/48,AUTO,no-resolve")
        out.append("  - IP-CIDR6,2001:b28:f23d::/48,AUTO,no-resolve")
        out.append("  - IP-CIDR6,2001:b28:f23f::/48,AUTO,no-resolve")
        out.append("  - IP-CIDR,203.208.43.0/24,AUTO,no-resolve")
        out.append("  - IP-CIDR,203.208.50.0/24,AUTO,no-resolve")
        # ── Final bypass ──
        out.append("  - GEOIP,CN,DIRECT")
        out.append("  - MATCH,AUTO")
    return "\n".join(out) + "\n"


def load_disk():
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            _cache.data["cn"] = f.read()
    except Exception:
        pass


def refresh_loop():
    while True:
        for lang in ("cn", "en"):
            try:
                refresh(lang)
                print("refreshed %s: %d links" % (lang, len(_cache.data[lang].splitlines())), flush=True)
            except Exception as e:
                _cache.last_error = "%s: %s" % (lang, e)
                print("refresh %s failed: %s" % (lang, e), flush=True)
        time.sleep(REFRESH)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        out = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(out)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(out)

    def _authorized(self, query):
        tok = urllib.parse.parse_qs(query).get("token", [""])[0]
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            tok = auth[7:].strip()
        return bool(tok) and hmac.compare_digest(tok, TOKEN)

    def _wants_clash(self):
        # Clash / Mihomo-family clients identify themselves in the User-Agent.
        # SubConverter-style negotiation: one subscription URL "just works"
        # in every client — Clash gets YAML, v2rayNG/NekoBox/Shadowrocket get
        # raw links. A client can also force YAML via the /clash path.
        ua = (self.headers.get("User-Agent") or "").lower()
        return any(m in ua for m in CLASH_UA_MARKERS)

    def _get_body(self, lang):
        if lang:
            with _cache.lock:
                return _cache.data.get(lang)
        return merged_data()  # locks exactly once, never nested

    def do_GET(self):
        p, _, q = self.path.partition("?")
        path = p.rstrip("/") or "/"
        if path not in ("/healthz", "/health") and not self._authorized(q):
            self._send(401, "unauthorized: missing or bad token\n", "text/plain")
            return
        if path in ("/healthz", "/health"):
            m = merged_data()  # locks once internally; never nested
            with _cache.lock:
                data = {
                    "ok": _cache.data.get("cn") is not None,
                    "fetched": _cache.last_fetch,
                    "error": _cache.last_error,
                    "cn_links": len((_cache.data.get("cn") or "").splitlines()),
                    "en_links": len((_cache.data.get("en") or "").splitlines()),
                    "merged_links": len((m or "").splitlines()),
                    "dropped_domains": dict(_cache.dropped),
                }
            self._send(200, json.dumps(data, indent=2), "application/json")
            return
        if path.startswith("/clash-ip"):
            sub = path[len("/clash-ip"):]  # "", "/cn", "/en"
            if sub in ("", "/cn", "/en"):
                lang = {"/cn": "cn", "/en": "en"}.get(sub)  # "" -> None = merged
                body = self._get_body(lang)
                if body is None:
                    self._send(503, "no data yet\n", "text/plain")
                    return
                self._send(200, clash_yaml(body, pin_ip=True),
                           "application/yaml; charset=utf-8")
            else:
                self._send(404, "not found\n", "text/plain")
            return
        if path.startswith("/clash"):
            sub = path[len("/clash"):]  # "", "/cn", "/en"
            if sub in ("", "/cn", "/en"):
                lang = {"/cn": "cn", "/en": "en"}.get(sub)  # "" -> None = merged
                body = self._get_body(lang)
                if body is None:
                    self._send(503, "no data yet\n", "text/plain")
                    return
                self._send(200, clash_yaml(body), "application/yaml; charset=utf-8")
            else:
                self._send(404, "not found\n", "text/plain")
            return
        if path.startswith("/cn"):
            lang = "cn"
        elif path.startswith("/en"):
            lang = "en"
        else:
            lang = None  # merged
        body = self._get_body(lang)
        if body is None:
            self._send(503, "no data yet\n", "text/plain")
            return
        if self._wants_clash():
            self._send(200, clash_yaml(body), "application/yaml; charset=utf-8")
        else:
            self._send(200, body, "text/plain; charset=utf-8")


def main():
    load_disk()
    t = threading.Thread(target=refresh_loop, daemon=True)
    t.start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("sub-proxy serving on :%d (refresh every %ds)" % (PORT, REFRESH), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
