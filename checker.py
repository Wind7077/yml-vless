#!/usr/bin/env python3
import re
import base64
import urllib.parse
import socket
import ssl
import time
import requests
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# --- Жёсткий белый список РФ (только проверенные крупные сервисы) ---
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
        if "vless://" in decoded:
            text = decoded
    except Exception:
        pass
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

        network = params.get('type', 'tcp')
        sni = params.get('sni', params.get('host', server))
        security = params.get('security', 'none')

        return {
            "name": name or f"{server}:{port}",
            "uuid": uuid, "server": server, "port": port,
            "sni": sni, "security": security, "network": network,
            "flow": params.get('flow', ''), "path": params.get('path', ''),
            "host": params.get('host', ''), "fp": params.get('fp', 'chrome'),
            "pbk": params.get('pbk', ''), "sid": params.get('sid', ''),
            "link": link
        }
    except Exception:
        return None

def test_node(node, timeout=5):
    try:
        start_time = time.time()
        sock = socket.create_connection((node['server'], node['port']), timeout=timeout)
        if node['security'] in ['tls', 'xtls', 'reality']:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=node['sni']) as ssock:
                pass
        latency = (time.time() - start_time) * 1000
        return {"node": node, "latency": latency, "status": "OK"}
    except Exception:
        return {"node": node, "latency": None, "status": "Fail"}

def build_clash_proxy(node):
    proxy = {
        'name': node['name'], 'type': 'vless',
        'server': node['server'], 'port': node['port'],
        'uuid': node['uuid'], 'udp': True,
        'network': node['network'],
        'tls': node['security'] in ['tls', 'xtls', 'reality'],
    }
    if node['security'] == 'reality':
        proxy['reality-opts'] = {}
        if node['pbk']: proxy['reality-opts']['public-key'] = node['pbk']
        if node['sid']: proxy['reality-opts']['short-id'] = node['sid']
    if node['flow']: proxy['flow'] = node['flow']
    if node['sni']: proxy['servername'] = node['sni']
    if node['fp']: proxy['client-fingerprint'] = node['fp']

    if node['network'] == 'ws':
        proxy['ws-opts'] = {}
        if node['path']: proxy['ws-opts']['path'] = node['path']
        if node['host']: proxy['ws-opts']['headers'] = {'Host': node['host']}
    elif node['network'] == 'grpc':
        if node['path']: proxy['grpc-opts'] = {'grpc-service-name': node['path']}
    elif node['network'] == 'tcp' and node['host']:
        proxy['tcp-opts'] = {'headers': {'Host': node['host']}}
    return proxy

def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Начало проверки...")
    try:
        with open('sub.txt', 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print("[-] Файл sub.txt не найден!")
        return
    except Exception as e:
        print(f"[-] Ошибка чтения sub.txt: {e}")
        return

    all_links = []
    for source in sources:
        if source.startswith('http'):
            print(f"[*] Загрузка: {source}")
            content = fetch_subscription(source)
            all_links.extend(extract_vless_links(content))
        elif source.startswith('vless://'):
            all_links.append(source)

    print(f"[*] Найдено сырых ссылок: {len(all_links)}")
    parsed_nodes = [n for n in (parse_vless(l) for l in all_links) if n]

    seen = set()
    unique_nodes = []
    for n in parsed_nodes:
        key = (n['uuid'], n['server'], n['port'])
        if key not in seen:
            seen.add(key)
            unique_nodes.append(n)

    rf_nodes = [n for n in unique_nodes if is_rf_domain(n['sni'])]
    print(f"[*] Уникальных нод: {len(unique_nodes)}")
    print(f"[*] Прошло строгий фильтр РФ SNI: {len(rf_nodes)}")

    if not rf_nodes:
        print("[!] Нод с разрешённым российским SNI не найдено. Очищаем выходные файлы.")
        open('vless.txt', 'w').close()
        with open('vless.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': [], 'proxy-groups': []}, f, allow_unicode=True)
        return

    print("[*] Проверка TCP+TLS пингом (многопоточно)...")
    results = []
    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = {executor.submit(test_node, node): node for node in rf_nodes}
        for future in as_completed(futures):
            results.append(future.result())

    ok_results = sorted([r for r in results if r['latency']], key=lambda x: x['latency'])
    print(f"[+] Живых нод: {len(ok_results)} из {len(rf_nodes)}")

    with open('vless.txt', 'w', encoding='utf-8') as f:
        for r in ok_results:
            f.write(r['node']['link'] + "\n")

    # --- Сохранение vless.yaml (Clash Meta / Mihomo) ---
    proxies = []
    seen_names = set()
    
    for r in ok_results:
        proxy = build_clash_proxy(r['node'])
        
        # 🛡️ ЗАЩИТА ОТ ДУБЛИКАТОВ ИМЁН (duplicate name fix)
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

    with open('vless.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    print(f"[*] Файлы vless.txt и vless.yaml успешно обновлены!")

if __name__ == "__main__":
    main()
