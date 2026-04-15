import requests
import re
import ipaddress
import socket
import yaml
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, unquote

URL_JSON = "https://tiagorrg.github.io/vless-checker/keys.json"
URL_HTML = "https://getfreeproxy.com/lists/vless-proxy-list"

# Российские ASN (основные провайдеры) - прокси с этих AS блокируем
RUSSIA_ASN_PREFIXES = [
    "AS8359",   # MTS
    "AS8402",   # Corbina / Beeline
    "AS3216",   # Vimpelcom / Beeline
    "AS25513",  # МТС
    "AS15582",  # Rostelecom (часть)
    "AS12389",  # Rostelecom
    "AS31133",  # Megafon
    "AS25159",  # Megafon
    "AS20632",  # Enforce (хостинг RU)
    "AS48642",  # Selectel (RU хостинг)
    "AS197695",  # reg.ru
    "AS9049",   # ERTelecom
    "AS35807",  # Yota
    "AS44812",  # ТТК
    "AS29648",  # ТТК
    "AS42610",  # Enforta
]

# Российские диапазоны IP (наиболее крупные блоки)
RUSSIA_IP_RANGES = [
    "5.3.0.0/16",
    "5.8.0.0/16",
    "5.16.0.0/13",
    "5.45.192.0/18",
    "5.53.32.0/21",
    "5.100.0.0/15",
    "31.13.0.0/18",
    "31.23.0.0/16",
    "31.148.0.0/16",
    "37.9.64.0/18",
    "37.29.0.0/16",
    "45.8.144.0/22",
    "45.128.128.0/18",
    "77.37.0.0/16",
    "77.72.128.0/18",
    "77.88.0.0/21",
    "78.24.136.0/21",
    "78.107.0.0/16",
    "79.133.0.0/16",
    "80.73.16.0/20",
    "81.176.235.0/24",
    "83.149.0.0/17",
    "84.201.128.0/17",
    "85.249.0.0/16",
    "89.108.64.0/18",
    "90.151.0.0/16",
    "91.108.4.0/22",    # Telegram (НЕ блокируем, но это пример)
    "92.53.0.0/18",
    "93.153.0.0/16",
    "94.25.0.0/16",
    "95.167.0.0/16",
    "109.86.0.0/15",
    "176.9.0.0/16",
    "178.216.0.0/14",
    "185.71.76.0/22",
    "188.93.16.0/21",
    "193.201.224.0/21",
    "194.85.0.0/16",
    "195.14.0.0/16",
    "195.190.0.0/17",
    "212.1.224.0/21",
    "213.87.128.0/18",
]

# Anycast диапазоны (Cloudflare, Google, Akamai и др.)
ANYCAST_RANGES = [
    "1.1.1.0/24",      # Cloudflare DNS anycast
    "1.0.0.0/24",      # Cloudflare DNS anycast
    "8.8.8.0/24",      # Google DNS anycast
    "8.8.4.0/24",      # Google DNS anycast
    "9.9.9.0/24",      # Quad9 DNS
    "208.67.222.0/24", # OpenDNS anycast
    "208.67.220.0/24", # OpenDNS anycast
    "4.2.2.0/24",      # Level3 anycast DNS
    "23.32.0.0/11",    # Akamai anycast range (широкий блок)
    "2.16.0.0/13",     # Akamai anycast
    "104.16.0.0/13",   # Cloudflare anycast
    "104.24.0.0/14",   # Cloudflare anycast
    "172.64.0.0/13",   # Cloudflare anycast
    "162.158.0.0/15",  # Cloudflare anycast
    "198.41.128.0/17", # Cloudflare anycast
]


def build_networks(ranges):
    """Парсим список CIDR в объекты сети."""
    nets = []
    for cidr in ranges:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    return nets


RUSSIA_NETS = build_networks(RUSSIA_IP_RANGES)
ANYCAST_NETS = build_networks(ANYCAST_RANGES)


def is_ipv6(host):
    """Проверяем — это IPv6-адрес?"""
    try:
        ipaddress.IPv6Address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_cidr(host):
    """Проверяем — это CIDR-нотация? (т.е. не конкретный хост)"""
    return "/" in host


def resolve_host(host):
    """Пытаемся получить IP для хоста. Если не получилось — возвращаем None."""
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except Exception:
        return None


def ip_in_networks(ip_str, networks):
    """Проверяем, входит ли IP в один из диапазонов."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def is_russia_or_bad(host):
    """
    Возвращает True если хост:
    - IPv6 (блокируем)
    - CIDR (блокируем)
    - Российский IP (блокируем)
    - Anycast (блокируем)
    """
    if is_ipv6(host):
        return True
    if is_cidr(host):
        return True

    # Пробуем резолвить домен в IP
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        ip = host
    else:
        ip = resolve_host(host)

    if ip is None:
        # Домен не резолвится — оставляем (может работать через proxy)
        return False

    if ip_in_networks(ip, RUSSIA_NETS):
        return True

    if ip_in_networks(ip, ANYCAST_NETS):
        return True

    return False


# ─── Загрузка источников ─────────────────────────────────────────────────────

def fetch_json():
    r = requests.get(URL_JSON, timeout=30)
    r.raise_for_status()
    return r.json()


def extract_json(data):
    result = []
    if not isinstance(data, dict):
        return result
    for k, v in data.items():
        if isinstance(v, dict):
            for kk in ["best", "top10", "top5", "top20", "all"]:
                val = v.get(kk)
                if isinstance(val, str) and val.startswith("vless://"):
                    result.append(val)
                elif isinstance(val, list):
                    for i in val:
                        if isinstance(i, str) and i.startswith("vless://"):
                            result.append(i)
                        elif isinstance(i, dict):
                            for x in ["key", "vless", "url"]:
                                if x in i and isinstance(i[x], str):
                                    result.append(i[x])
    return result


def fetch_html():
    try:
        r = requests.get(URL_HTML, timeout=30)
        r.raise_for_status()
        return re.findall(r'vless://[^\s"<]+', r.text)
    except Exception:
        return []


# ─── Парсинг и валидация ──────────────────────────────────────────────────────

def normalize(v):
    return v.strip()


def is_valid(v):
    return isinstance(v, str) and v.startswith("vless://") and len(v) > 50


def parse_vless_uri(uri):
    """
    Разбирает vless:// URI и возвращает словарь параметров.
    Формат: vless://UUID@HOST:PORT?параметры#имя
    """
    try:
        # Убираем схему
        rest = uri[len("vless://"):]

        # Разделяем UUID от остального
        at_pos = rest.find("@")
        if at_pos == -1:
            return None
        uuid = rest[:at_pos]
        rest = rest[at_pos + 1:]

        # Разделяем host:port от параметров
        # Учитываем IPv6 в скобках [::1]:443
        if rest.startswith("["):
            bracket_end = rest.find("]")
            if bracket_end == -1:
                return None
            host = rest[1:bracket_end]
            rest = rest[bracket_end + 1:]
            if rest.startswith(":"):
                rest = rest[1:]
        else:
            if ":" not in rest:
                return None
            host, rest = rest.split(":", 1)

        # Отделяем port от параметров
        port_str = rest.split("?")[0].split("#")[0]
        try:
            port = int(port_str)
        except ValueError:
            return None

        # Парсим query-параметры
        q_start = rest.find("?")
        fragment = ""
        params = {}

        if q_start != -1:
            query_and_frag = rest[q_start + 1:]
            frag_pos = query_and_frag.find("#")
            if frag_pos != -1:
                fragment = unquote(query_and_frag[frag_pos + 1:])
                query_str = query_and_frag[:frag_pos]
            else:
                query_str = query_and_frag
            for part in query_str.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = unquote(v)
        else:
            frag_pos = rest.find("#")
            if frag_pos != -1:
                fragment = unquote(rest[frag_pos + 1:])

        return {
            "uuid": uuid,
            "host": host,
            "port": port,
            "params": params,
            "name": fragment or f"{host}:{port}",
            "raw": uri,
        }
    except Exception:
        return None


# ─── Генерация Clash YAML ─────────────────────────────────────────────────────

def vless_to_clash_proxy(parsed):
    """
    Конвертирует разобранный vless URI в proxy-запись для Clash Meta / Mihomo.
    Поддерживает transport: ws, grpc, tcp.
    TLS и XTLS поддерживаются.
    """
    p = parsed["params"]
    name = parsed["name"][:50]  # Clash ограничивает длину имени

    # Базовая структура
    proxy = {
        "name": name,
        "type": "vless",
        "server": parsed["host"],
        "port": parsed["port"],
        "uuid": parsed["uuid"],
        "udp": True,
    }

    # Flow (для XTLS / Vision)
    flow = p.get("flow", "")
    if flow:
        proxy["flow"] = flow

    # TLS
    security = p.get("security", "none")
    if security in ("tls", "reality", "xtls"):
        proxy["tls"] = True
        sni = p.get("sni") or p.get("host") or parsed["host"]
        proxy["servername"] = sni

        fp = p.get("fp", "chrome")
        proxy["client-fingerprint"] = fp

        # ALPN
        alpn = p.get("alpn", "")
        if alpn:
            proxy["alpn"] = alpn.split(",")

        # Reality
        if security == "reality":
            proxy["reality-opts"] = {
                "public-key": p.get("pbk", ""),
                "short-id": p.get("sid", ""),
            }
    else:
        proxy["tls"] = False

    # Skip-cert-verify (по умолчанию False — безопаснее)
    proxy["skip-cert-verify"] = False

    # Transport
    transport = p.get("type", "tcp")
    if transport == "ws":
        ws_opts = {}
        ws_path = p.get("path", "/")
        ws_host = p.get("host", parsed["host"])
        ws_opts["path"] = ws_path
        ws_opts["headers"] = {"Host": ws_host}
        proxy["network"] = "ws"
        proxy["ws-opts"] = ws_opts
    elif transport == "grpc":
        grpc_service = p.get("serviceName", "")
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": grpc_service}
    elif transport == "httpupgrade":
        proxy["network"] = "httpupgrade"
        proxy["httpupgrade-opts"] = {
            "path": p.get("path", "/"),
            "host": p.get("host", parsed["host"]),
        }
    else:
        proxy["network"] = "tcp"

    return proxy


def generate_clash_yaml(proxies_list, filename="clash_vless.yaml"):
    """
    Генерирует полный Clash Meta / Mihomo конфиг с:
    - Прокси списком
    - Группами (авто-выбор, ручной выбор, fallback)
    - Правилами для Telegram и прямого доступа к RU ресурсам
    """
    clash_proxies = []
    proxy_names = []

    for uri in proxies_list:
        parsed = parse_vless_uri(uri)
        if parsed is None:
            continue
        clash_proxy = vless_to_clash_proxy(parsed)
        clash_proxies.append(clash_proxy)
        proxy_names.append(clash_proxy["name"])

    if not clash_proxies:
        print("WARN: Нет валидных прокси для Clash YAML")
        return

    config = {
        # ── Базовые настройки ──────────────────────────────────────────────
        "mixed-port": 7890,          # HTTP + SOCKS5 на одном порту
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,               # Отключаем IPv6 — нам не нужен

        # ── DNS ───────────────────────────────────────────────────────────
        "dns": {
            "enable": True,
            "ipv6": False,
            "listen": "0.0.0.0:53",
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            # Не применяем fake-ip к локальным адресам
            "fake-ip-filter": [
                "*.lan",
                "*.local",
                "localhost.ptlogin2.qq.com",
            ],
            "nameserver": [
                "https://8.8.8.8/dns-query",
                "https://1.1.1.1/dns-query",
            ],
            "fallback": [
                "https://8.8.4.4/dns-query",
                "tls://1.0.0.1:853",
            ],
            # Российские домены резолвим через российский DNS напрямую
            "nameserver-policy": {
                "geosite:ru": "114.114.114.114",
                "geosite:private": "direct",
            },
        },

        # ── Прокси ────────────────────────────────────────────────────────
        "proxies": clash_proxies,

        # ── Группы прокси ─────────────────────────────────────────────────
        "proxy-groups": [
            {
                "name": "🚀 Авто (лучший пинг)",
                "type": "url-test",
                "proxies": proxy_names,
                "url": "https://api.telegram.org",  # Тест именно Telegram
                "interval": 300,
                "tolerance": 50,
                "lazy": True,
            },
            {
                "name": "📌 Ручной выбор",
                "type": "select",
                "proxies": ["🚀 Авто (лучший пинг)"] + proxy_names,
            },
            {
                "name": "🔄 Fallback",
                "type": "fallback",
                "proxies": proxy_names,
                "url": "https://api.telegram.org",
                "interval": 180,
            },
            {
                "name": "🎯 Telegram",
                "type": "select",
                "proxies": ["🚀 Авто (лучший пинг)", "🔄 Fallback", "📌 Ручной выбор"],
            },
            {
                "name": "🇷🇺 Прямое подключение (RU)",
                "type": "select",
                "proxies": ["DIRECT"],
            },
            {
                "name": "🚫 Блокировка",
                "type": "select",
                "proxies": ["REJECT"],
            },
        ],

        # ── Правила маршрутизации ─────────────────────────────────────────
        "rules": [
            # Telegram — всегда через прокси
            "DOMAIN-SUFFIX,telegram.org,🎯 Telegram",
            "DOMAIN-SUFFIX,telegram.me,🎯 Telegram",
            "DOMAIN-SUFFIX,t.me,🎯 Telegram",
            "DOMAIN-SUFFIX,telegra.ph,🎯 Telegram",
            "DOMAIN-SUFFIX,tdesktop.com,🎯 Telegram",
            "IP-CIDR,91.108.4.0/22,🎯 Telegram,no-resolve",
            "IP-CIDR,91.108.8.0/22,🎯 Telegram,no-resolve",
            "IP-CIDR,91.108.12.0/22,🎯 Telegram,no-resolve",
            "IP-CIDR,91.108.16.0/22,🎯 Telegram,no-resolve",
            "IP-CIDR,91.108.56.0/22,🎯 Telegram,no-resolve",
            "IP-CIDR,149.154.160.0/20,🎯 Telegram,no-resolve",
            "IP-CIDR,185.76.151.0/24,🎯 Telegram,no-resolve",

            # Локальные адреса — напрямую
            "DOMAIN-SUFFIX,local,🇷🇺 Прямое подключение (RU)",
            "IP-CIDR,127.0.0.0/8,🇷🇺 Прямое подключение (RU)",
            "IP-CIDR,172.16.0.0/12,🇷🇺 Прямое подключение (RU)",
            "IP-CIDR,192.168.0.0/16,🇷🇺 Прямое подключение (RU)",
            "IP-CIDR,10.0.0.0/8,🇷🇺 Прямое подключение (RU)",

            # Российские ресурсы — напрямую (закомментируй если не нужно)
            "GEOSITE,ru,🇷🇺 Прямое подключение (RU)",
            "GEOIP,RU,🇷🇺 Прямое подключение (RU)",

            # Всё остальное — через прокси
            "MATCH,📌 Ручной выбор",
        ],
    }

    # Сохраняем с правильными отступами
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# Clash Meta / Mihomo VLESS config\n")
        f.write(f"# updated: {datetime.now(timezone.utc)}\n")
        f.write(f"# proxies: {len(clash_proxies)}\n\n")
        yaml.dump(
            config,
            f,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            indent=2,
        )

    print(f"CLASH YAML: {filename} ({len(clash_proxies)} proxies)")


# ─── Основная логика ──────────────────────────────────────────────────────────

def main():
    all_vless = []

    try:
        json_data = fetch_json()
        all_vless.extend(extract_json(json_data))
    except Exception as e:
        print("JSON error:", e)

    all_vless.extend(fetch_html())

    cleaned = [normalize(v) for v in all_vless if is_valid(v)]

    # Дедупликация с сохранением порядка
    unique = list(dict.fromkeys(cleaned))
    print(f"RAW TOTAL: {len(unique)}")

    # ── Фильтрация плохих прокси ──────────────────────────────────────────
    filtered = []
    skipped_ipv6 = 0
    skipped_cidr = 0
    skipped_russia = 0
    skipped_anycast = 0

    for v in unique:
        parsed = parse_vless_uri(v)
        if parsed is None:
            continue

        host = parsed["host"]

        if is_ipv6(host):
            skipped_ipv6 += 1
            continue

        if is_cidr(host):
            skipped_cidr += 1
            continue

        # Резолвим IP для проверки
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            ip = host
        else:
            ip = resolve_host(host)

        if ip:
            if ip_in_networks(ip, RUSSIA_NETS):
                skipped_russia += 1
                continue
            if ip_in_networks(ip, ANYCAST_NETS):
                skipped_anycast += 1
                continue

        filtered.append(v)

    print(f"Отфильтровано IPv6: {skipped_ipv6}")
    print(f"Отфильтровано CIDR: {skipped_cidr}")
    print(f"Отфильтровано RU: {skipped_russia}")
    print(f"Отфильтровано anycast: {skipped_anycast}")
    print(f"FINAL TOTAL: {len(filtered)}")

    if not filtered:
        raise RuntimeError("Empty VLESS list after filtering")

    # ── Сохраняем обычный txt ─────────────────────────────────────────────
    with open("vless_normal_vpn.txt", "w", encoding="utf-8") as f:
        f.write(f"# updated: {datetime.now(timezone.utc)}\n")
        f.write(f"# total: {len(filtered)}\n")
        for v in filtered:
            f.write(v + "\n")

    # ── Генерируем Clash YAML ─────────────────────────────────────────────
    generate_clash_yaml(filtered, "clash_vless.yaml")


if __name__ == "__main__":
    main()
