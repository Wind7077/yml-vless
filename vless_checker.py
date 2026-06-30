import re
import base64
import urllib.parse
import socket
import ssl
import time
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 1. Белый список доменов РФ ---
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

# --- 2. Парсинг ссылок ---
def extract_vless_links(text):
    # Пытаемся декодировать Base64 (если это файл подписки)
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
            "name": name,
            "uuid": uuid,
            "server": server,
            "port": port,
            "sni": params.get('sni', [server])[0],
            "security": params.get('security', ['none'])[0],
            "link": link
        }
    except Exception: return None

# --- 3. Проверка (TCP + TLS Handshake Ping) ---
def test_node(node, timeout=4):
    try:
        start_time = time.time()
        # TCP Connect
        sock = socket.create_connection((node['server'], node['port']), timeout=timeout)
        
        # TLS Handshake с подменой SNI
        if node['security'] in ['tls', 'xtls', 'reality']:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=node['sni']) as ssock:
                pass # Если дошли сюда - SNI принят, сервер валиден
                
        latency = (time.time() - start_time) * 1000
        return {"node": node, "latency": latency, "status": "OK"}
    except Exception as e:
        return {"node": node, "latency": None, "status": f"Fail"}

def main():
    if len(sys.argv) < 2:
        print("Использование: python vless_checker.py <путь_к_файлу.txt>")
        return
        
    filepath = sys.argv[1]
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Ошибка чтения файла: {e}")
        return
        
    links = extract_vless_links(content)
    print(f"[*] Найдено сырых ссылок: {len(links)}")
    
    parsed_nodes = [n for n in (parse_vless(l) for l in links) if n]
    
    # Фильтрация по РФ
    rf_nodes = [n for n in parsed_nodes if is_rf_domain(n['sni'])]
    print(f"[*] Отфильтровано по SNI (РФ): {len(rf_nodes)} нод")
    
    if not rf_nodes:
        print("[!] Нод с российским SNI не найдено.")
        return
        
    # Многопоточная проверка
    print("[*] Запуск TCP+TLS пинга (проверка на доступность и DPI)...")
    results = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(test_node, node): node for node in rf_nodes}
        for future in as_completed(futures):
            results.append(future.result())
            
    # Сортировка по пингу
    ok_results = sorted([r for r in results if r['latency']], key=lambda x: x['latency'])
    
    print("\n" + "="*60)
    print(f"{'Статус':<10} | {'Пинг':<8} | {'Имя и SNI':<40}")
    print("="*60)
    
    for r in ok_results:
        n = r['node']
        print(f"{'[OK]':<10} | {r['latency']:<8.2f} | {n['name'][:20]} ({n['sni']})")
        
    print(f"\nИтого живых нод: {len(ok_results)} из {len(rf_nodes)}")
    
    # Сохранение результата
    with open("working_rf_nodes.txt", "w", encoding="utf-8") as f:
        for r in ok_results:
            f.write(r['node']['link'] + "\n")
    print(f"[*] Живые ссылки сохранены в working_rf_nodes.txt")

if __name__ == "__main__":
    main()
