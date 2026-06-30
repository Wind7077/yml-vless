#!/usr/bin/env python3
import re
import base64
import urllib.parse
import socket
import ssl
import time
import sys
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Белый список доменов РФ
RF_TLDS = ['.ru', '.su', '.xn--p1ai', '.rf']
RF_DOMAINS = [
    'yandex.ru', 'yandex.com', 'ya.ru', 'vk.com', 'vk.ru',
    'mail.ru', 'list.ru', 'bk.ru', 'inbox.ru', 'rambler.ru',
    'sberbank.ru', 'sberbank.com', 'gosuslugi.ru', 'mos.ru', 'gov.ru',
    'tinkoff.ru', 'vtb.ru', 'mvideo.ru', 'rzd.ru', 'aeroflot.ru',
    'wildberries.ru', 'ozon.ru', 'dns-shop.ru', 'citilink.ru'
]

def is_rf_domain(domain):
    if not domain: return False
    domain = domain.lower()
    for tld in RF_TLDS:
        if domain.endswith(tld): return True
    return domain in RF_DOMAINS

def fetch_subscription(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=15)
        return response.text
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return ""

def extract_vless_links(text):
    try:
        padded_text = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(padded_text).decode('utf-8')
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
            name = urllib.parse.unquote(name)
        params = {}
        if '?' in body:
            base, params_str = body.split('?', 1)
            params = urllib.parse.parse_qs(params_str)
        else:
            base = body
        if '@' not in base: return None
        uuid, server_port = base.split('@', 1)
        server, port = (server_port.rsplit(':', 1) + [443])[:2]
        port = int(port)
        return {
            "name": name, "uuid": uuid, "server": server, "port": port,
            "sni": params.get('sni', [server])[0],
            "security": params.get('security', ['none'])[0],
            "link": link
        }
    except Exception: return None

def test_node(node, timeout=4):
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

def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Начало проверки...")
    try:
        with open('sub.txt', 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"Ошибка чтения sub.txt: {e}")
        return
    print(f"[*] Источников: {len(sources)}")
    all_links = []
    for source in sources:
        if source.startswith('http'):
            content = fetch_subscription(source)
            all_links.extend(extract_vless_links(content))
        elif source.startswith('vless://'):
            all_links.append(source)
    print(f"[*] Сырых ссылок: {len(all_links)}")
    parsed_nodes = [n for n in (parse_vless(l) for l in all_links) if n]
    rf_nodes = [n for n in parsed_nodes if is_rf_domain(n['sni'])]
    print(f"[*] РФ SNI: {len(rf_nodes)}")
    if not rf_nodes:
        print("[!] РФ нод не найдено.")
        return
    print("[*] Проверка...")
    results = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(test_node, node): node for node in rf_nodes}
        for future in as_completed(futures):
            results.append(future.result())
    ok_results = sorted([r for r in results if r['latency']], key=lambda x: x['latency'])
    print(f"\nИтого живых: {len(ok_results)} из {len(rf_nodes)}")
    
    os.makedirs('output', exist_ok=True)
    with open('output/working.txt', 'w', encoding='utf-8') as f:
        for r in ok_results:
            f.write(r['node']['link'] + "\n")
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_sources": len(sources),
        "total_links": len(all_links),
        "rf_nodes": len(rf_nodes),
        "working_nodes": len(ok_results),
        "nodes": [{"name": r['node']['name'], "server": r['node']['server'],
                   "port": r['node']['port'], "sni": r['node']['sni'],
                   "latency": round(r['latency'], 2), "link": r['node']['link']}
                  for r in ok_results]
    }
    with open('output/report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    with open('output/report.txt', 'w', encoding='utf-8') as f:
        f.write(f"Отчёт от {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*70 + "\n")
        f.write(f"Источников: {len(sources)}\n")
        f.write(f"Всего ссылок: {len(all_links)}\n")
        f.write(f"РФ SNI: {len(rf_nodes)}\n")
        f.write(f"Рабочих: {len(ok_results)}\n")
        f.write("="*70 + "\n\n")
        for r in ok_results:
            n = r['node']
            f.write(f"✓ {n['name'][:30]}\n")
            f.write(f"  Сервер: {n['server']}:{n['port']}\n")
            f.write(f"  SNI: {n['sni']}\n")
            f.write(f"  Пинг: {r['latency']:.2f} ms\n\n")
    print("[*] Результаты в output/")

if __name__ == "__main__":
    import os
    main()
