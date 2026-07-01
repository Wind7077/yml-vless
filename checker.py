#!/usr/bin/env python3
import re
import os
import json
import stat
import tempfile
import zipfile
import itertools
import threading
import subprocess
import base64
import urllib.parse
import socket
import ssl
import time
import requests
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# --- Настройки проверки через реальный даунлоад файла (вместо TCP/TLS пинга) ---
XRAY_BIN = os.environ.get('XRAY_BIN', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'xray'))
XRAY_DOWNLOAD_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
DOWNLOAD_TEST_URL = os.environ.get('DOWNLOAD_TEST_URL', 'https://speed.cloudflare.com/__down?bytes=102400')
MIN_DOWNLOAD_BYTES = 20 * 1024   # меньше - считаем обрыв/затык, не реальная нода
XRAY_STARTUP_TIMEOUT = 3.0       # сколько ждём, пока локальный SOCKS5-порт поднимется
DOWNLOAD_TIMEOUT = 8             # таймаут на сам HTTP-запрос через прокси
DOWNLOAD_WORKERS = int(os.environ.get('DOWNLOAD_WORKERS', '10'))  # параллельных xray-процессов

_port_lock = threading.Lock()
_port_counter = itertools.count(20000)

try:
    import socks  # noqa: F401  -- из пакета PySocks (requests[socks])
    SOCKS_SUPPORT = True
    _SOCKS_IMPORT_ERROR = None
except ImportError as e:
    SOCKS_SUPPORT = False
    _SOCKS_IMPORT_ERROR = str(e)

# --- Жёсткий белый список РФ ---
RF_DOMAINS = [
    'gosuslugi.ru', 'gov.ru', 'kremlin.ru', 'government.ru', 'mos.ru',
    'nalog.ru', 'fss.ru', 'pfr.ru', 'sfr.gov.ru',
    'yandex.ru', 'yandex.com', 'yandex.net', 'ya.ru', 'yandex-team.ru',
    'yandexcloud.net', 'kinopoisk.ru', 'auto.ru', 'avito.ru',
    'vk.com', 'vk.ru', 'vk.me', 'vk.link', 'vk.team',
    'mail.ru', 'list.ru', 'bk.ru', 'inbox.ru', 'rambler.ru',
    'ok.ru', 'my.mail.ru',
    'sberbank.ru', 'sberbank.com', 'sberbank.com.ru',
    'tinkoff.ru', 'tinkoff.com', 'tbank.ru',
    'vtb.ru', 'vtb.com', 'alfabank.ru', 'alfabank.com',
    'gazprombank.ru', 'raiffeisen.ru', 'rosbank.ru',
    'qiwi.com', 'qiwi.ru', 'yoomoney.ru',
    'mts.ru', 'beeline.ru', 'megafon.ru', 'tele2.ru',
    'rostelecom.ru', 'rt.ru', 'dom.ru',
    'rzd.ru', 'aeroflot.ru', 's7.ru', 'pobeda.aero', 'tutu.ru',
    'ria.ru', 'tass.ru', 'interfax.ru', 'rbc.ru',
    'vedomosti.ru', 'kommersant.ru', 'iz.ru',
    'ntv.ru', '1tv.ru', 'vgtrk.com', 'smotrim.ru',
    'wildberries.ru', 'ozon.ru', 'dns-shop.ru', 'citilink.ru',
    'mvideo.ru', 'eldorado.ru', 'leroymerlin.ru',
    'pikabu.ru', 'habr.com', 'habr.ru',
    'hh.ru', 'superjob.ru', 'rabota.ru',
    'cian.ru', 'domclick.ru',
    'kaspersky.ru', 'kaspersky.com', 'drweb.ru',
    'cloud.mail.ru', 'disk.yandex.ru', 'cloud.yandex.ru',
]

UUID_REGEX = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
VALID_FPS = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'random', 'randomized']
VALID_NETWORKS = ['tcp', 'ws', 'grpc', 'h2', 'http', 'xhttp']

def is_rf_domain(domain):
    if not domain: return False
    domain = domain.lower().strip()
    for allowed in RF_DOMAINS:
        if domain == allowed or domain.endswith('.' + allowed):
            return True
    return False

def fetch_subscription(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"[-] Ошибка загрузки {url}: {e}")
        return ""

def extract_vless_links(text):
    if not text: return []
    try:
        padded = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
        if "vless://" in decoded: text = decoded
    except Exception: pass
    return re.findall(r'vless://[^\s<>"\']+', text)

def parse_vless(link):
    try:
        link = link.strip()
        if not link.startswith("vless://"): return None
        body = link[8:]
        name = "Unknown"
        if '#' in body:
            body, name = body.split('#', 1)
            name = urllib.parse.unquote(name).strip()
        params = {}
        if '?' in body:
            base, params_str = body.split('?', 1)
            params = {k: v[0] for k, v in urllib.parse.parse_qs(params_str).items()}
        else:
            base = body
        if '@' not in base: return None
        uuid, server_port = base.split('@', 1)
        server, port = (server_port.rsplit(':', 1) + [443])[:2]
        try: port = int(port)
        except: return None

        return {
            "name": name or f"{server}:{port}",
            "uuid": uuid, "server": server, "port": port,
            "sni": params.get('sni', params.get('host', server)),
            "security": params.get('security', 'none'),
            "network": params.get('type', 'tcp'),
            "flow": params.get('flow', ''), "path": params.get('path', ''),
            "host": params.get('host', ''), "fp": params.get('fp', 'randomized'),
            "pbk": params.get('pbk', ''), "sid": params.get('sid', ''),
            "mode": params.get('mode', ''),
            "link": link
        }
    except Exception: return None

def is_valid_vless(node):
    if not node: return False
    if not UUID_REGEX.match(node.get('uuid', '')): return False
    if not node.get('sni'): return False
    
    is_reality = node.get('security') == 'reality'
    has_vision = 'vision' in node.get('flow', '')
    if is_reality or has_vision:
        if not node.get('pbk'): return False
        if has_vision and not is_reality:
            node['security'] = 'reality'
            
    if node.get('network') not in VALID_NETWORKS:
        node['network'] = 'tcp'
        
    fp = node.get('fp', '').lower().strip()
    if fp not in VALID_FPS:
        node['fp'] = 'randomized'
        
    return True

def test_node(node, timeout=5):
    """Быстрый stage-1 фильтр: просто TCP+TLS рукопожатие.
    Отсекает явно мёртвые сервера/порты, но НЕ гарантирует,
    что VLESS через них реально работает (особенно REALITY,
    где TLS-рукопожатие идёт на decoy-сайт)."""
    try:
        start_time = time.time()
        sock = socket.create_connection((node['server'], node['port']), timeout=timeout)
        if node['security'] in ['tls', 'xtls', 'reality']:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=node['sni']) as ssock:
                pass
        else:
            sock.close()
        latency = (time.time() - start_time) * 1000
        return {"node": node, "latency": latency, "status": "OK"}
    except Exception:
        return {"node": node, "latency": None, "status": "Fail"}


def ensure_xray_binary():
    """Гарантирует наличие исполняемого xray по пути XRAY_BIN.
    Если бинарника нет - пытается скачать последний релиз linux-64.
    Если в вашем CI xray уже ставится отдельным шагом (apt/cache/release-action) -
    просто прокиньте путь через переменную окружения XRAY_BIN, и сюда код не зайдёт."""
    if os.path.isfile(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK):
        return True
    try:
        print(f"[*] xray не найден по пути {XRAY_BIN}, скачиваю...")
        tmp_zip = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
        tmp_zip.close()
        resp = requests.get(XRAY_DOWNLOAD_URL, timeout=60, stream=True)
        resp.raise_for_status()
        with open(tmp_zip.name, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)
        with zipfile.ZipFile(tmp_zip.name) as zf:
            zf.extract('xray', os.path.dirname(XRAY_BIN) or '.')
        extracted = os.path.join(os.path.dirname(XRAY_BIN) or '.', 'xray')
        if extracted != XRAY_BIN:
            os.replace(extracted, XRAY_BIN)
        st = os.stat(XRAY_BIN)
        os.chmod(XRAY_BIN, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        os.unlink(tmp_zip.name)
        print("[*] xray скачан и готов.")
        return True
    except Exception as e:
        print(f"[-] Не удалось скачать xray: {e}. Проверка скачиванием файла будет пропущена.")
        return False


def get_free_port():
    global _port_counter
    with _port_lock:
        for _ in range(2000):
            port = next(_port_counter)
            if port > 60000:
                _port_counter = itertools.count(20000)
                continue
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
            finally:
                s.close()
    raise RuntimeError("Не удалось найти свободный порт")


def build_xray_outbound(node):
    """VLESS outbound для клиентского конфига Xray-core.
    Соответствие network -> streamSettings:
      tcp   -> network: tcp (без header-обфускации)
      ws    -> network: ws,   wsSettings {path, headers}
      grpc  -> network: grpc, grpcSettings {serviceName}
      http  -> network: tcp,  tcpSettings.header (HTTP/1.1 disguise, как в исходных VLESS-ссылках)
      h2    -> network: http, httpSettings {path, host[]}   (в Xray JSON "http" == HTTP/2 мультиплекс)
      xhttp -> network: xhttp, xhttpSettings {path, host, mode}
    """
    net = node['network']
    security = node.get('security', 'none')

    p = node.get('path', '') or ''
    if isinstance(p, list):
        p = p[0] if p else ''
    p = str(p).strip()
    host = str(node.get('host', '') or '').strip()

    stream_settings = {"network": net}

    if security in ('tls', 'xtls'):
        stream_settings['security'] = 'tls'
        stream_settings['tlsSettings'] = {
            'serverName': node['sni'],
            'allowInsecure': True,
            'fingerprint': node.get('fp') or 'chrome',
        }
    elif security == 'reality':
        stream_settings['security'] = 'reality'
        reality_settings = {
            'serverName': node['sni'],
            'publicKey': node['pbk'],
            'fingerprint': node.get('fp') or 'chrome',
            'show': False,
        }
        sid = str(node.get('sid', '')).strip()
        if sid:
            reality_settings['shortId'] = sid
        stream_settings['realitySettings'] = reality_settings

    if net == 'ws':
        ws = {'path': p or '/'}
        if host:
            ws['headers'] = {'Host': host}
        stream_settings['wsSettings'] = ws

    elif net == 'grpc':
        stream_settings['grpcSettings'] = {'serviceName': p}

    elif net == 'http':
        stream_settings['network'] = 'tcp'
        tcp_request = {'path': [p or '/']}
        if host:
            tcp_request['headers'] = {'Host': [host]}
        stream_settings['tcpSettings'] = {
            'header': {'type': 'http', 'request': tcp_request}
        }

    elif net == 'h2':
        stream_settings['network'] = 'http'
        stream_settings['httpSettings'] = {
            'path': p or '/',
            'host': [host] if host else [],
        }

    elif net == 'xhttp':
        xhttp = {'path': p or '/', 'mode': node.get('mode') or 'auto'}
        if host:
            xhttp['host'] = host
        stream_settings['xhttpSettings'] = xhttp

    user = {'id': node['uuid'], 'encryption': 'none'}
    if node.get('flow') and security in ('tls', 'xtls', 'reality'):
        # flow (xtls-rprx-vision) валиден только поверх TLS/REALITY и только на tcp/xhttp
        if net in ('tcp', 'xhttp'):
            user['flow'] = node['flow']

    return {
        'tag': 'proxy',
        'protocol': 'vless',
        'settings': {
            'vnext': [{
                'address': node['server'],
                'port': node['port'],
                'users': [user],
            }]
        },
        'streamSettings': stream_settings,
    }


def download_test(node, xray_available, fallback_timeout=5):
    """Stage-2: поднимаем ноду как локальный SOCKS5 через xray и реально
    качаем через неё небольшой файл. Это ловит нерабочие REALITY/xhttp
    ноды, которые проходят TCP/TLS-пинг, но не проксируют трафик."""
    if not xray_available:
        return test_node(node, timeout=fallback_timeout)

    port = get_free_port()
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": {"udp": False, "auth": "noauth"}
        }],
        "outbounds": [build_xray_outbound(node)],
    }

    cfg_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8')
    json.dump(config, cfg_file)
    cfg_file.close()

    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg_file.name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # ждём, пока локальный SOCKS5-порт реально откроется
        deadline = time.time() + XRAY_STARTUP_TIMEOUT
        up = False
        while time.time() < deadline:
            if proc.poll() is not None:
                break  # xray упал сразу - битый конфиг/протокол
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                    up = True
                    break
            except OSError:
                time.sleep(0.1)

        if not up:
            return {"node": node, "latency": None, "status": "Fail"}

        proxies = {
            'http': f'socks5h://127.0.0.1:{port}',
            'https': f'socks5h://127.0.0.1:{port}',
        }

        start_time = time.time()
        r = requests.get(DOWNLOAD_TEST_URL, proxies=proxies, timeout=DOWNLOAD_TIMEOUT, stream=True)
        received = 0
        for chunk in r.iter_content(chunk_size=16384):
            received += len(chunk)
            if received >= MIN_DOWNLOAD_BYTES:
                break
        latency = (time.time() - start_time) * 1000

        if r.status_code == 200 and received >= MIN_DOWNLOAD_BYTES:
            return {"node": node, "latency": latency, "status": "OK"}
        return {"node": node, "latency": None, "status": "Fail"}

    except Exception:
        return {"node": node, "latency": None, "status": "Fail"}
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            os.unlink(cfg_file.name)
        except OSError:
            pass

def build_clash_proxy(node):
    proxy = {
        'name': node['name'], 'type': 'vless',
        'server': node['server'], 'port': node['port'],
        'uuid': node['uuid'], 'udp': True,
        'network': node['network'],
        'tls': node['security'] in ['tls', 'xtls', 'reality'],
    }

    if node['security'] == 'reality':
        reality_opts = {'public-key': node['pbk']}
        sid = str(node.get('sid', '')).strip()
        if sid and re.fullmatch(r'[0-9a-fA-F]+', sid):
            if len(sid) % 2 != 0:
                sid = '0' + sid
            if len(sid) <= 16:
                reality_opts['short-id'] = sid
        proxy['reality-opts'] = reality_opts

    if node.get('flow'): proxy['flow'] = node['flow']
    if node.get('sni'): proxy['servername'] = node['sni']
    if node.get('fp'): proxy['client-fingerprint'] = node['fp']

    net = node['network']

    # path может прийти списком (на всякий случай) - всегда сводим к одной строке
    p = node.get('path', '')
    if isinstance(p, list):
        p = p[0] if p else ''
    p = str(p).strip()
    host = str(node.get('host', '') or '').strip()

    # --- ИСПРАВЛЕНИЕ OPTS: типы полей строго по структурам mihomo (адаптер VLESS) ---
    if net == 'ws':
        # ws-opts: path -> string, headers -> map[string]string
        ws_opts = {}
        if p: ws_opts['path'] = p
        if host: ws_opts['headers'] = {'Host': host}
        if ws_opts: proxy['ws-opts'] = ws_opts

    elif net == 'grpc':
        # grpc-opts: grpc-service-name -> string
        if p: proxy['grpc-opts'] = {'grpc-service-name': p}

    elif net == 'http':
        # http-opts (HTTP/1.1 "disguise"): path -> []string, headers -> map[string][]string
        # ВАЖНО: оба поля - именно СПИСКИ, в т.ч. headers - список значений на каждый заголовок.
        # Раньше headers писался как {'Host': host} (просто строка) - это и давало
        # ошибку парсера "cannot unmarshal !!str into []string" при импорте в FlClash.
        http_opts = {}
        if p: http_opts['path'] = [p]
        if host: http_opts['headers'] = {'Host': [host]}
        if http_opts: proxy['http-opts'] = http_opts

    elif net == 'h2':
        # h2-opts (настоящий HTTP/2): host -> []string, path -> string (НЕ список!)
        # Раньше h2 ошибочно писался в http-opts с path-списком - mihomo при
        # network: h2 этот блок вообще не читает (читает h2-opts), в итоге
        # транспорт уходил с дефолтными path "/" и пустым host.
        h2_opts = {}
        if host: h2_opts['host'] = [host]
        if p: h2_opts['path'] = p
        if h2_opts: proxy['h2-opts'] = h2_opts

    elif net == 'xhttp':
        # xhttp-opts (Xray-совместимый SplitHTTP): path/host -> string, mode -> string
        # Раньше xhttp вообще никак не обрабатывался - блок opts не создавался,
        # нода уходила без path/host/mode и просто не коннектилась.
        xhttp_opts = {}
        if p: xhttp_opts['path'] = p
        if host: xhttp_opts['host'] = host
        xhttp_opts['mode'] = node.get('mode') or 'auto'
        proxy['xhttp-opts'] = xhttp_opts

    # network == 'tcp': никаких *-opts для VLESS в mihomo не предусмотрено.
    # Раньше сюда ошибочно писался 'tcp-opts' - такого поля у VLESS-прокси в
    # mihomo вообще нет (это легаси-поле VMess), могло провоцировать ошибки
    # парсинга в более строгих сборках/версиях.

    return proxy

def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Начало проверки...")
    try:
        with open('sub.txt', 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print("[-] Файл sub.txt не найден!")
        return

    all_links = []
    for source in sources:
        if source.startswith('http'):
            content = fetch_subscription(source)
            all_links.extend(extract_vless_links(content))
        elif source.startswith('vless://'):
            all_links.append(source)

    parsed_nodes = [n for n in (parse_vless(l) for l in all_links) if is_valid_vless(n)]
    
    seen = set()
    unique_nodes = []
    for n in parsed_nodes:
        key = (n['uuid'], n['server'], n['port'])
        if key not in seen:
            seen.add(key)
            unique_nodes.append(n)

    rf_nodes = [n for n in unique_nodes if is_rf_domain(n['sni'])]
    print(f"[*] Валидных РФ нод после чистки: {len(rf_nodes)}")

    if not rf_nodes:
        open('vless.txt', 'w').close()
        with open('vless.yaml', 'w', encoding='utf-8') as f:
            f.write("proxies: []\nproxy-groups: []\n")
        return

    print(f"[*] Stage 1: быстрый TCP/TLS отсев ({len(rf_nodes)} нод)...")
    prefilter_results = []
    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = {executor.submit(test_node, node): node for node in rf_nodes}
        for future in as_completed(futures):
            prefilter_results.append(future.result())

    alive_nodes = [r['node'] for r in prefilter_results if r['latency'] is not None]
    print(f"[*] Прошли TCP/TLS: {len(alive_nodes)} из {len(rf_nodes)}")

    if not alive_nodes:
        open('vless.txt', 'w').close()
        with open('vless.yaml', 'w', encoding='utf-8') as f:
            f.write("proxies: []\nproxy-groups: []\n")
        return

    xray_available = ensure_xray_binary()
    if xray_available and not SOCKS_SUPPORT:
        import sys
        print(f"[-] Не найден пакет PySocks (нужен для socks5h:// в requests). "
              f"Установите: pip install pysocks --break-system-packages")
        print(f"[-] Debug: python executable = {sys.executable}")
        print(f"[-] Debug: import error = {_SOCKS_IMPORT_ERROR}")
        xray_available = False
    if xray_available:
        print(f"[*] Stage 2: реальное скачивание файла через каждую ноду (xray, {DOWNLOAD_WORKERS} потоков)...")
    else:
        print("[*] Stage 2 пропущен (xray недоступен) - используем результат TCP/TLS отсева")

    results = []
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        futures = {executor.submit(download_test, node, xray_available): node for node in alive_nodes}
        for future in as_completed(futures):
            results.append(future.result())

    ok_results = sorted([r for r in results if r['latency']], key=lambda x: x['latency'])
    print(f"[*] Реально рабочих нод: {len(ok_results)} из {len(alive_nodes)}")

    with open('vless.txt', 'w', encoding='utf-8') as f:
        for r in ok_results:
            f.write(r['node']['link'] + "\n")

    proxies = []
    seen_names = set()
    for r in ok_results:
        proxy = build_clash_proxy(r['node'])
        base_name = proxy['name']
        unique_name = base_name
        counter = 2
        while unique_name in seen_names:
            unique_name = f"{base_name} ({counter})"
            counter += 1
        proxy['name'] = unique_name
        seen_names.add(unique_name)
        proxies.append(proxy)
        
    proxy_names = [p['name'] for p in proxies]

    clash_config = {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule',
        'log-level': 'info', 'unified-delay': True, 'tcp-concurrent': True,
        'dns': {
            'enable': True, 'listen': '0.0.0.0:1053', 'enhanced-mode': 'fake-ip',
            'nameserver': ['https://dns.yandex.ru/dns-query', 'https://cloudflare-dns.com/dns-query']
        },
        'proxies': proxies,
        'proxy-groups': [
            {'name': 'RF-Proxy', 'type': 'select', 'proxies': proxy_names + ['DIRECT']},
            {'name': 'Auto-Optimal', 'type': 'url-test', 'proxies': proxy_names, 'url': 'https://yandex.ru', 'interval': 300}
        ],
        'rules': [
            'DOMAIN-SUFFIX,ru,RF-Proxy',
            'DOMAIN-SUFFIX,xn--p1ai,RF-Proxy',
            'MATCH,Auto-Optimal'
        ]
    }

    # Генерируем YAML
    yaml_str = yaml.dump(clash_config, allow_unicode=True, sort_keys=False, default_flow_style=False)
    
    # 🛡️ БРОНЯ ОТ ПАРСЕРА YAML (Принудительные кавычки для чисел/хешей)
    yaml_str = re.sub(r'(?m)^(\s*short-id:\s*)([0-9a-fA-F]+)$', r'\1"\2"', yaml_str)
    yaml_str = re.sub(r'(?m)^(\s*public-key:\s*)([0-9a-zA-Z_\-]+)$', r'\1"\2"', yaml_str)
    yaml_str = re.sub(r'(?m)^(\s*uuid:\s*)([0-9a-fA-F\-]+)$', r'\1"\2"', yaml_str)
    
    # Удаление пустых short-id, если они просочились
    yaml_str = re.sub(r'(?m)^\s*short-id:\s*(null|None|)\s*$', '', yaml_str)

    with open('vless.yaml', 'w', encoding='utf-8') as f:
        f.write(yaml_str)

    print(f"[*] Готово! Конфиг на 100% совместим с Mihomo (Clash Meta).")

if __name__ == "__main__":
    main()
