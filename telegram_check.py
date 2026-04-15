import subprocess
import json
import tempfile
import time
import requests
import os
import re
from urllib.parse import unquote

INPUT = "vless_normal_vpn.txt"
OUTPUT = "vless_normal_vpn.txt"  # Перезаписываем тот же файл

# Тестируем именно Telegram API
TEST_URL = "https://api.telegram.org"
TEST_TIMEOUT = 10
SINGBOX_STARTUP_WAIT = 2.5  # Секунды ожидания запуска sing-box


def parse_vless(vless_uri):
    """
    Парсер vless:// URI для sing-box конфига.
    Поддерживает: tcp, ws, grpc, reality, tls, xtls.
    """
    try:
        rest = vless_uri[len("vless://"):]
        at_pos = rest.find("@")
        uuid = rest[:at_pos]
        rest = rest[at_pos + 1:]

        # IPv6 хост в скобках
        if rest.startswith("["):
            bracket_end = rest.find("]")
            host = rest[1:bracket_end]
            rest = rest[bracket_end + 2:]  # пропускаем ]:
        else:
            host, rest = rest.split(":", 1)

        port_str = rest.split("?")[0].split("#")[0]
        port = int(port_str)

        # Параметры
        params = {}
        q_pos = rest.find("?")
        if q_pos != -1:
            query = rest[q_pos + 1:]
            frag_pos = query.find("#")
            if frag_pos != -1:
                query = query[:frag_pos]
            for part in query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = unquote(v)

        security = params.get("security", "none")
        transport = params.get("type", "tcp")
        sni = params.get("sni") or params.get("host") or host
        fp = params.get("fp", "chrome")
        flow = params.get("flow", "")

        # ── TLS ────────────────────────────────────────────────────────
        tls_config = None
        if security in ("tls", "xtls"):
            tls_config = {
                "enabled": True,
                "server_name": sni,
                "utls": {
                    "enabled": True,
                    "fingerprint": fp,
                }
            }
        elif security == "reality":
            tls_config = {
                "enabled": True,
                "server_name": sni,
                "reality": {
                    "enabled": True,
                    "public_key": params.get("pbk", ""),
                    "short_id": params.get("sid", ""),
                },
                "utls": {
                    "enabled": True,
                    "fingerprint": fp,
                },
            }

        # ── Транспорт ─────────────────────────────────────────────────
        transport_config = None
        if transport == "ws":
            ws_host = params.get("host", host)
            ws_path = params.get("path", "/")
            transport_config = {
                "type": "ws",
                "path": ws_path,
                "headers": {"Host": ws_host},
                "max_early_data": 2048,
                "early_data_header_name": "Sec-WebSocket-Protocol",
            }
        elif transport == "grpc":
            transport_config = {
                "type": "grpc",
                "service_name": params.get("serviceName", ""),
            }
        elif transport == "httpupgrade":
            transport_config = {
                "type": "httpupgrade",
                "host": params.get("host", host),
                "path": params.get("path", "/"),
            }
        elif transport == "http":
            transport_config = {
                "type": "http",
                "host": [params.get("host", host)],
                "path": params.get("path", "/"),
            }

        # ── Собираем outbound ──────────────────────────────────────────
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": uuid,
            "packet_encoding": "xudp",  # Важно для UDP / QUIC
        }

        if flow:
            outbound["flow"] = flow

        if tls_config:
            outbound["tls"] = tls_config

        if transport_config:
            outbound["transport"] = transport_config

        return outbound

    except Exception as e:
        raise ValueError(f"Parse error: {e}")


def build_config(vless):
    """Строим полный sing-box конфиг для тестирования."""
    outbound = parse_vless(vless)

    return {
        "log": {"level": "error"},
        "dns": {
            "servers": [
                {
                    "tag": "google",
                    "address": "8.8.8.8",
                    "strategy": "ipv4_only",  # Только IPv4
                }
            ],
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1080,
                "sniff": True,
            }
        ],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "final": "proxy",
            "rules": [
                {
                    # Локальный трафик напрямую
                    "ip_is_private": True,
                    "outbound": "direct",
                }
            ],
        },
    }


def check(vless):
    """Тестируем прокси через sing-box, проверяем доступность Telegram."""
    try:
        cfg = build_config(vless)
    except ValueError:
        return False

    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False
    ) as f:
        json.dump(cfg, f, ensure_ascii=False)
        path = f.name

    p = None
    try:
        p = subprocess.Popen(
            ["sing-box", "run", "-c", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(SINGBOX_STARTUP_WAIT)

        # Проверяем что процесс ещё жив
        if p.poll() is not None:
            return False

        r = requests.get(
            TEST_URL,
            proxies={
                "http": "socks5h://127.0.0.1:1080",
                "https": "socks5h://127.0.0.1:1080",
            },
            timeout=TEST_TIMEOUT,
        )

        # Telegram API возвращает 200 или 401 — оба значат что соединение прошло
        return r.status_code in (200, 401)

    except Exception:
        return False

    finally:
        if p:
            p.kill()
            p.wait(timeout=3)
        try:
            os.remove(path)
        except Exception:
            pass


def main():
    with open(INPUT, "r", encoding="utf-8") as f:
        vless_list = [x.strip() for x in f if x.strip().startswith("vless://")]

    good = []
    total = len(vless_list)
    print(f"TESTING: {total}")

    for i, v in enumerate(vless_list):
        result = check(v)
        status = "✓ OK" if result else "✗ FAIL"
        print(f"{i + 1}/{total} {status}")
        if result:
            good.append(v)

    print(f"\nGOOD: {len(good)} / {total}")

    # Перезаписываем файл только рабочими прокси
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("# telegram-ok only\n")
        f.write(f"# good: {len(good)}\n")
        for v in good:
            f.write(v + "\n")

    # Если есть модуль для генерации Clash — регенерируем и его
    try:
        from merge_vless import generate_clash_yaml
        generate_clash_yaml(good, "clash_vless.yaml")
        print("Clash YAML обновлён")
    except Exception as e:
        print(f"Clash YAML не обновлён: {e}")


if __name__ == "__main__":
    main()
