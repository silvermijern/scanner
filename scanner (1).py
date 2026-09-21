#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Proxy Panel Scanner v7 — نسخه آنلاین (Railway / VPS / Termux)
- پورت‌ها: 1081, 1082, 1083, 14111
- تشخیص خودکار: SOCKS5 / SOCKS4 / HTTP CONNECT / HTTP Forward
- Egress (IP خروجی) + پرچم + کشور + ISP
- پینگ اصلی پنل + تأخیر واقعی
- فیلتر + مرتب‌سازی + تست مجدد

اجرا محلی:   python scanner.py  →  http://127.0.0.1:5000
اجرا Railway: خودکار با Dockerfile
"""

import json
import os
import re
import socket
import ssl
import struct
import threading
import time
import ipaddress
from urllib.request import urlopen
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= پورت وب‌سرور =================
PORT = int(os.environ.get('PORT', 5000))

# ================= پورت‌های اسکن =================
SCAN_PORTS = [1081, 1082, 1083, 14111]
MAX_RANGE = 65536

cfg = {'port_timeout': 3, 'proxy_timeout': 8}

GEO_HOST = 'ip-api.com'


def _resolve_geo():
    try:
        return socket.gethostbyname(GEO_HOST)
    except Exception:
        return '208.95.112.1'


GEO_IP = _resolve_geo()
GEO_PATH = '/json?fields=status,query,country,countryCode,isp'

# ================= وضعیت =================
state = {
    'collected_pairs': [],
    'scan_results': [],
    'running': False,
    'stop_flag': False,
    'total': 0, 'done': 0, 'alive': 0,
    'opened': 0, 'closed': 0, 'http_fail': 0,
}
lock = threading.Lock()

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# ================= اسم فارسی کشورها =================
FA = {
    'US': 'آمریکا', 'DE': 'آلمان', 'NL': 'هلند', 'FR': 'فرانسه', 'GB': 'انگلستان',
    'TR': 'ترکیه', 'AE': 'امارات', 'RU': 'روسیه', 'BR': 'برزیل', 'ES': 'اسپانیا',
    'IT': 'ایتالیا', 'CA': 'کانادا', 'IN': 'هند', 'CN': 'چین', 'JP': 'ژاپن',
    'KR': 'کره جنوبی', 'SG': 'سنگاپور', 'SE': 'سوئد', 'FI': 'فنلاند', 'PL': 'لهستان',
    'UA': 'اوکراین', 'IR': 'ایران', 'IQ': 'عراق', 'AF': 'افغانستان', 'PK': 'پاکستان',
    'AZ': 'آذربایجان', 'AM': 'ارمنستان', 'GE': 'گرجستان', 'KZ': 'قزاقستان',
    'AT': 'اتریش', 'CH': 'سوئیس', 'CZ': 'چک', 'RO': 'رومانی', 'MD': 'مولداوی',
    'LT': 'لیتوانی', 'LV': 'لتونی', 'EE': 'استونی', 'BG': 'بلغارستان', 'HU': 'مجارستان',
    'GR': 'یونان', 'PT': 'پرتغال', 'DK': 'دانمارک', 'NO': 'نروژ', 'IE': 'ایرلند',
    'BE': 'بلژیک', 'AU': 'استرالیا', 'NZ': 'نیوزیلند', 'ZA': 'آفریقای جنوبی',
    'AR': 'آرژانتین', 'CL': 'شیلی', 'MX': 'مکزیک', 'CO': 'کلمبیا', 'PE': 'پرو',
    'TH': 'تایلند', 'VN': 'ویتنام', 'ID': 'اندونزی', 'MY': 'مالزی', 'PH': 'فیلیپین',
    'TW': 'تایوان', 'HK': 'هنگ‌کنگ', 'IL': 'اسرائیل', 'SA': 'عربستان', 'QA': 'قطر',
    'KW': 'کویت', 'OM': 'عمان', 'BH': 'بحرین', 'JO': 'اردن', 'LB': 'لبنان',
    'EG': 'مصر', 'MA': 'مراکش', 'DZ': 'الجزایر', 'TN': 'تونس', 'LY': 'لیبی',
}


def flag_emoji(cc):
    if not cc or len(cc) != 2:
        return '❓'
    try:
        return ''.join(chr(ord(c) + 127397) for c in cc.upper())
    except Exception:
        return '❓'


# ================= اطلاعات خود پنل =================
_panel_cache = None
_panel_lock = threading.Lock()


def get_panel_info():
    """IP خروجی سرور پنل + پینگ واقعی پنل (TCP به 1.1.1.1 - ۳ بار، کمترین)"""
    global _panel_cache
    with _panel_lock:
        if _panel_cache is not None:
            return _panel_cache

    info = {'ip': '—', 'country': '', 'country_fa': '—', 'cc': '',
            'flag': '❓', 'ping': 0, 'uptime': int(time.time())}

    # پینگ واقعی پنل
    pings = []
    for _ in range(3):
        t0 = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(4)
                if s.connect_ex(('1.1.1.1', 443)) == 0:
                    pings.append(int((time.time() - t0) * 1000))
        except Exception:
            pass
        time.sleep(0.1)
    info['ping'] = min(pings) if pings else 0

    # IP خروجی سرور پنل
    try:
        with urlopen('http://ip-api.com/json/?fields=status,query,country,countryCode',
                     timeout=6) as r:
            d = json.loads(r.read().decode('utf-8', 'ignore'))
        if d.get('status') == 'success':
            cc = d.get('countryCode', '')
            info.update({
                'ip': d.get('query', '—'),
                'country': d.get('country', ''),
                'cc': cc,
                'flag': flag_emoji(cc),
                'country_fa': FA.get(cc, d.get('country', '—')),
            })
    except Exception:
        pass

    _panel_cache = info
    return info


# ================= ابزارهای شبکه =================
def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(cfg['port_timeout'])
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def http_over_socket(s):
    """GET به ip-api از داخل تانل پروکسی"""
    req = ("GET " + GEO_PATH + " HTTP/1.1\r\nHost: " + GEO_HOST +
           "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n").encode()
    s.sendall(req)
    data = b''
    try:
        while len(data) < 65536:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data


def parse_geo(body):
    """پارس JSON داخل پاسخ HTTP خام"""
    try:
        i, j = body.find(b'{'), body.rfind(b'}')
        if i == -1 or j == -1 or j <= i:
            return None
        d = json.loads(body[i:j + 1].decode('utf-8', 'ignore'))
        if d.get('status') == 'success' and d.get('query'):
            cc = d.get('countryCode', '??')
            return {
                'query': d.get('query', ''),
                'country': d.get('country', 'Unknown'),
                'cc': cc,
                'flag': flag_emoji(cc),
                'country_fa': FA.get(cc, d.get('country', 'Unknown')),
                'isp': d.get('isp', 'نامشخص'),
            }
    except Exception:
        pass
    return None


# ================= تست پروتکل‌ها =================
def socks5_test(ip, port):
    """SOCKS5 بدون احراز هویت"""
    s = None
    try:
        t0 = time.time()
        s = socket.create_connection((ip, port), timeout=cfg['proxy_timeout'])
        s.settimeout(cfg['proxy_timeout'])
        s.sendall(b'\x05\x01\x00')
        r = s.recv(2)
        if len(r) < 2 or r[0] != 0x05 or r[1] != 0x00:
            return None
        s.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(GEO_IP) + struct.pack('>H', 80))
        r = s.recv(1024)
        if len(r) < 4 or r[1] != 0x00:
            return None
        body = http_over_socket(s)
        ms = int((time.time() - t0) * 1000)
        return ms, parse_geo(body)
    except Exception:
        return None
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


def socks4_test(ip, port):
    """SOCKS4"""
    s = None
    try:
        t0 = time.time()
        s = socket.create_connection((ip, port), timeout=cfg['proxy_timeout'])
        s.settimeout(cfg['proxy_timeout'])
        s.sendall(struct.pack('>BBH', 4, 1, 80) + socket.inet_aton(GEO_IP) + b'\x00')
        r = s.recv(8)
        if len(r) < 8 or r[1] != 0x00:
            return None
        body = http_over_socket(s)
        ms = int((time.time() - t0) * 1000)
        return ms, parse_geo(body)
    except Exception:
        return None
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


def http_connect_test(ip, port):
    """HTTP CONNECT"""
    s = None
    try:
        t0 = time.time()
        s = socket.create_connection((ip, port), timeout=cfg['proxy_timeout'])
        s.settimeout(cfg['proxy_timeout'])
        s.sendall(("CONNECT " + GEO_IP + ":80 HTTP/1.1\r\nHost: " +
                   GEO_HOST + ":80\r\n\r\n").encode())
        buf = b''
        while b'\r\n\r\n' not in buf and len(buf) < 8192:
            c = s.recv(1024)
            if not c:
                break
            buf += c
        first = buf.split(b'\r\n', 1)[0]
        if b' 200' not in first:
            return None
        body = http_over_socket(s)
        ms = int((time.time() - t0) * 1000)
        return ms, parse_geo(body)
    except Exception:
        return None
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


def http_forward_test(ip, port):
    """HTTP Forward (GET مطلق)"""
    s = None
    try:
        t0 = time.time()
        s = socket.create_connection((ip, port), timeout=cfg['proxy_timeout'])
        s.settimeout(cfg['proxy_timeout'])
        s.sendall(("GET http://" + GEO_HOST + GEO_PATH + " HTTP/1.1\r\nHost: " +
                   GEO_HOST + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n").encode())
        data = b''
        try:
            while len(data) < 65536:
                c = s.recv(4096)
                if not c:
                    break
                data += c
        except Exception:
            pass
        first = data.split(b'\r\n', 1)[0]
        if b'HTTP/1' not in first:
            return None
        ms = int((time.time() - t0) * 1000)
        info = parse_geo(data)
        if info is None:
            return None
        return ms, info
    except Exception:
        return None
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


def check_proxy(ip, port):
    """تشخیص خودکار پروتکل و گرفتن Egress — فقط پروکسی واقعی سالم ثبت میشه"""
    opened = check_port(ip, port)
    with lock:
        if opened:
            state['opened'] += 1
        else:
            state['closed'] += 1
    if not opened:
        return None

    for proto, fn in (('socks', socks5_test), ('socks', socks4_test),
                      ('http', http_connect_test), ('http', http_forward_test)):
        with lock:
            if state['stop_flag']:
                return None
        r = fn(ip, port)
        if r:
            ms, info = r
            if info:
                return {
                    'ip': ip, 'port': port, 'proto': proto, 'latency': ms,
                    'exit_ip': info['query'], 'country': info['country'],
                    'country_fa': info['country_fa'], 'cc': info['cc'],
                    'flag': info['flag'], 'isp': info['isp'],
                }
            return {
                'ip': ip, 'port': port, 'proto': proto, 'latency': ms,
                'exit_ip': '', 'country': 'Unknown', 'country_fa': 'نامشخص',
                'cc': '??', 'flag': '❓', 'isp': 'نامشخص',
            }

    with lock:
        state['http_fail'] += 1
    return None


# ================= جمع‌آوری IP =================
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def collect_pairs(custom_text, cidr_text):
    """جمع‌آوری: IP تکی، IP:Port، رنج CIDR"""
    pairs = []
    seen = set()

    def add(ip, port=None):
        if ip not in seen:
            seen.add(ip)
            pairs.append((ip, port))

    if custom_text and custom_text.strip():
        for p in re.split(r'[\n,;\s]+', custom_text.strip()):
            p = p.strip()
            if not p:
                continue
            # IP:Port
            if ':' in p and '/' not in p:
                ip, _, pt = p.rpartition(':')
                if validate_ip(ip) and pt.isdigit():
                    add(ip, int(pt))
                continue
            # رنج
            if '/' in p:
                try:
                    net = ipaddress.ip_network(p, strict=False)
                    if net.num_addresses <= MAX_RANGE:
                        for h in net.hosts():
                            add(str(h))
                except Exception:
                    pass
            # IP تکی
            elif validate_ip(p):
                add(p)

    if cidr_text and cidr_text.strip():
        try:
            net = ipaddress.ip_network(cidr_text.strip(), strict=False)
            if net.num_addresses > MAX_RANGE:
                return None, "رنج خیلی بزرگه! حداکثر " + str(MAX_RANGE) + " IP"
            for h in net.hosts():
                add(str(h))
        except Exception:
            return None, "رنج نامعتبر: " + cidr_text

    if not pairs:
        return None, "هیچ IP معتبری پیدا نشد!"
    return pairs, None


# ================= اجرای اسکن =================
def run_scan(threads):
    """اسکن: هر IP بدون پورت → هر ۴ پورت | هر IP:Port → فقط همون"""
    with lock:
        pairs = list(state['collected_pairs'])
        tasks = []
        tseen = set()
        for ip, pt in pairs:
            plist = [pt] if pt else SCAN_PORTS
            for p in plist:
                k = (ip, p)
                if k not in tseen:
                    tseen.add(k)
                    tasks.append(k)
        state.update(running=True, stop_flag=False, total=len(tasks),
                     done=0, alive=0, opened=0, closed=0, http_fail=0,
                     scan_results=[])

    ex = ThreadPoolExecutor(max_workers=threads)
    CHUNK = max(threads * 10, 2000)
    try:
        for i in range(0, len(tasks), CHUNK):
            with lock:
                if state['stop_flag']:
                    break
            batch = tasks[i:i + CHUNK]
            futs = [ex.submit(check_proxy, ip, p) for ip, p in batch]
            for f in as_completed(futs):
                try:
                    r = f.result()
                except Exception:
                    r = None
                with lock:
                    state['done'] += 1
                    if r:
                        state['alive'] += 1
                        state['scan_results'].append(r)
    finally:
        try:
            ex.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            ex.shutdown(wait=False)
        with lock:
            state['running'] = False


def run_retest():
    """تست مجدد همه پروکسی‌های پیدا شده — مرده‌ها حذف میشن"""
    with lock:
        results = list(state['scan_results'])
        state.update(running=True, stop_flag=False,
                     total=len(results), done=0, alive=0,
                     opened=0, closed=0, http_fail=0)
    ex = ThreadPoolExecutor(max_workers=50)
    try:
        futs = [ex.submit(retest_one, r) for r in results]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception:
                pass
            with lock:
                state['done'] += 1
                state['alive'] += 1
    finally:
        try:
            ex.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            ex.shutdown(wait=False)
        with lock:
            state['running'] = False


def retest_one(r):
    fn = socks5_test if r.get('proto') == 'socks' else http_connect_test
    res = fn(r['ip'], r['port'])
    if res is None and r.get('proto') == 'socks':
        res = socks4_test(r['ip'], r['port'])
    if res is None:
        res = http_forward_test(r['ip'], r['port'])
    with lock:
        if res:
            ms, info = res
            r['latency'] = ms
            if info:
                r['exit_ip'] = info['query']
                r['country'] = info['country']
                r['country_fa'] = info['country_fa']
                r['cc'] = info['cc']
                r['flag'] = info['flag']
                r['isp'] = info['isp']
        else:
            state['scan_results'] = [x for x in state['scan_results']
                                     if not (x['ip'] == r['ip'] and x['port'] == r['port'])]


# ================= تست سلامت سرور پنل =================
def direct_http(ip, port, tls=False):
    try:
        s = socket.create_connection((ip, port), timeout=5)
        s.settimeout(5)
        if tls:
            s = ssl_ctx.wrap_socket(s)
        s.sendall(b"GET / HTTP/1.1\r\nHost: " + ip.encode() +
                  b"\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        d = s.recv(512)
        s.close()
        return d.startswith(b'HTTP/')
    except Exception:
        return False


TEST_TARGETS = [
    ('1.1.1.1', 80, False), ('1.1.1.1', 443, True),
    ('8.8.8.8', 443, True), ('104.16.132.229', 80, False),
]


def run_selftest():
    out = []
    for ip, port, tls in TEST_TARGETS:
        e = {'target': ip + ':' + str(port), 'ok': False, 'note': ''}
        if check_port(ip, port):
            if direct_http(ip, port, tls):
                e['ok'] = True
                e['note'] = 'HTTP OK'
            else:
                e['note'] = 'پورت باز، HTTP خطا'
        else:
            e['note'] = 'پورت بسته'
        out.append(e)
    return out


# ================= خروجی متنی =================
def stamp():
    return time.strftime('%Y%m%d_%H%M')


def sorted_results():
    with lock:
        return sorted(state['scan_results'], key=lambda x: (x['latency'], x['ip']))


def build_text(dl=False):
    res = sorted_results()
    L = []
    if dl:
        L += ["Proxy Panel Scanner Results - " + time.strftime('%Y-%m-%d %H:%M'),
              "Ports: " + ', '.join(str(p) for p in SCAN_PORTS),
              "=" * 60, ""]
    for r in res:
        L += [
            r['flag'] + " " + r['ip'] + ":" + str(r['port']) + "  [" + r['proto'] + "]",
            "   Egress  : " + (r['exit_ip'] or '—') + " (" + r['country_fa'] + " / " + r['country'] + ") [" + r['cc'] + "]",
            "   ISP     : " + r['isp'],
            "   Latency : " + str(r['latency']) + " ms",
            "-" * 44,
        ]
    L += ["", "Total: " + str(len(res)) + " working proxies"]
    return "\n".join(L)


# ================= صفحه وب =================
HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Proxy Panel Scanner - Online</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:Tahoma,Arial,sans-serif; background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);
       color:#e8eaf0; min-height:100vh; padding:15px; }
.container { max-width:760px; margin:0 auto; }
.header { text-align:center; padding:18px 0; }
.header h1 { font-size:2em; background:linear-gradient(90deg,#00d2ff,#928dab);
             -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.header p { color:#888; font-size:.85em; margin-top:5px; }
.panelbar { display:none; align-items:center; gap:10px; flex-wrap:wrap;
            background:rgba(0,210,255,.06); border:1px solid rgba(0,210,255,.25);
            border-radius:14px; padding:13px 16px; margin-bottom:16px; }
.panelbar .t { color:#00d2ff; font-weight:bold; font-size:.85em; }
.panelbar .pi { font-family:monospace; direction:ltr; background:rgba(0,0,0,.4);
                padding:5px 12px; border-radius:8px; font-size:.9em; }
.panelbar .eg2 { display:inline-flex; align-items:center; gap:6px; padding:5px 12px;
                 border-radius:8px; background:rgba(0,0,0,.35); font-size:.9em; }
.panelbar .pg { margin-right:auto; padding:5px 14px; border-radius:14px;
                background:rgba(76,175,80,.18); color:#7ee787; font-weight:bold; font-size:.85em; }
.panelbar .pg.mid { background:rgba(255,209,0,.15); color:#ffd200; }
.panelbar .lbl2 { color:#8892a6; font-size:.8em; }
.step { background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.1);
        border-radius:16px; padding:20px; margin-bottom:16px; }
.step-title { display:flex; align-items:center; gap:10px; margin-bottom:14px; font-weight:bold; flex-wrap:wrap; }
.step-num { width:30px; height:30px; border-radius:50%; background:linear-gradient(135deg,#00d2ff,#3a7bd5);
            display:flex; align-items:center; justify-content:center; font-size:.85em; flex-shrink:0; }
input, textarea, select { width:100%; padding:12px 15px; border:1px solid rgba(255,255,255,.2);
       border-radius:10px; background:rgba(0,0,0,.35); color:#fff; font-size:14px;
       outline:none; font-family:inherit; }
textarea { min-height:110px; resize:vertical; font-family:monospace; }
textarea::placeholder, input::placeholder { color:#555; }
input:focus, textarea:focus, select:focus { border-color:#00d2ff; }
select option { background:#1a1a2e; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
@media(max-width:640px){ .grid2{ grid-template-columns:1fr; } }
.lbl { color:#9aa; font-size:.82em; margin-bottom:6px; display:block; }
button { padding:12px 24px; border:none; border-radius:10px; font-size:14px; font-weight:bold;
         cursor:pointer; font-family:inherit; transition:.25s; }
button:disabled { opacity:.4; cursor:not-allowed; }
.b-confirm { background:linear-gradient(135deg,#f7971e,#ffd200); color:#222; width:100%; margin-top:14px; }
.b-scan { background:linear-gradient(135deg,#00d2ff,#3a7bd5); color:#fff; }
.b-test { background:rgba(255,255,255,.1); color:#bbb; width:100%; margin-top:10px; }
.b-copy { background:linear-gradient(135deg,#11998e,#38ef7d); color:#fff; }
.b-dl { background:linear-gradient(135deg,#f7971e,#ffd200); color:#222; }
.b-gray { background:rgba(255,255,255,.1); color:#bbb; }
.b-row { display:flex; gap:10px; flex-wrap:wrap; margin-top:14px; }
.ip-list { background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.1); border-radius:10px;
           padding:12px; max-height:180px; overflow-y:auto; font-family:monospace; font-size:12px;
           line-height:1.8; direction:ltr; text-align:left; white-space:pre; }
.badge { padding:3px 12px; border-radius:20px; font-size:.75em; background:rgba(0,210,255,.15); color:#00d2ff; }
.pbar { height:9px; background:rgba(255,255,255,.1); border-radius:5px; overflow:hidden; margin-top:10px; }
.pfill { height:100%; width:0%; background:linear-gradient(90deg,#00d2ff,#3a7bd5); transition:width .4s; }
.ptext { display:flex; justify-content:space-between; margin-top:7px; font-size:.85em; color:#9aa; }
.pulse { animation:pulse 1.4s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
.stats { display:grid; grid-template-columns:repeat(4,1fr); gap:9px; margin-top:14px; }
@media(max-width:560px){ .stats{ grid-template-columns:repeat(2,1fr); } }
.stat { background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.1);
        border-radius:12px; padding:11px; text-align:center; }
.stat .n { font-size:1.4em; font-weight:bold; }
.stat .l { color:#888; font-size:.72em; margin-top:2px; }
.stat.g .n { color:#38ef7d; } .stat.y .n { color:#ffd200; }
.stat.c .n { color:#00d2ff; } .stat.r .n { color:#ff4b6b; }
.diag { display:none; margin-top:13px; padding:13px; border-radius:10px; font-size:.85em; line-height:1.9; }
.diag.warn { display:block; background:rgba(255,209,0,.08); border:1px solid rgba(255,209,0,.3); color:#ffd200; }
.diag.good { display:block; background:rgba(56,239,125,.08); border:1px solid rgba(56,239,125,.3); color:#38ef7d; }
.toolbar { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:14px; }
.chipbtn { padding:8px 16px; border-radius:20px; font-size:.8em; background:rgba(255,255,255,.08);
           color:#aab; border:1px solid rgba(255,255,255,.12); cursor:pointer; }
.chipbtn.on { background:rgba(0,210,255,.2); color:#00d2ff; border-color:rgba(0,210,255,.4); }
.cards { display:flex; flex-direction:column; gap:12px; }
.pcard { background:rgba(255,255,255,.055); border:1px solid rgba(255,255,255,.1);
         border-radius:16px; padding:16px; }
.pcard-top { display:flex; align-items:center; gap:10px; }
.pcard-top .idx { font-weight:bold; font-size:1.05em; }
.proto { padding:3px 12px; border-radius:14px; font-size:.75em; font-weight:bold; }
.proto.socks { background:rgba(76,175,80,.18); color:#7ee787; }
.proto.http { background:rgba(33,150,243,.18); color:#64b5f6; }
.lat { margin-right:auto; padding:4px 12px; border-radius:14px; font-size:.78em; font-weight:bold;
       background:rgba(76,175,80,.15); color:#7ee787; }
.lat.mid { background:rgba(255,209,0,.15); color:#ffd200; }
.lat.bad { background:rgba(255,75,107,.15); color:#ff7b96; }
.chipip { display:inline-block; margin-top:10px; padding:5px 12px; border-radius:8px;
          background:rgba(0,0,0,.4); font-family:monospace; font-size:.95em; color:#00d2ff;
          direction:ltr; }
.prow { display:flex; align-items:center; gap:8px; margin-top:9px; font-size:.88em; flex-wrap:wrap; }
.prow .k { color:#8892a6; }
.eg { display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:8px;
      background:rgba(0,0,0,.35); border:1px solid rgba(255,255,255,.08); }
.eg .f { font-size:1.2em; }
.v4 { font-family:monospace; direction:ltr; color:#aab; }
.pbottom { display:flex; align-items:center; margin-top:10px; gap:8px; }
.traffic { color:#4a5568; font-size:.8em; direction:ltr; }
.bolt { margin-right:auto; width:40px; height:40px; border-radius:50%; font-size:1.1em;
        background:linear-gradient(135deg,#3a7bd5,#00d2ff); color:#fff; border:none; cursor:pointer; }
.empty { text-align:center; padding:35px; color:#556; }
.empty .ic { font-size:3em; margin-bottom:8px; }
.toast { position:fixed; bottom:20px; left:50%; transform:translateX(-50%);
         background:#11998e; color:#fff; padding:13px 26px; border-radius:10px;
         display:none; z-index:999; max-width:90vw; }
</style>
</head>
<body>
<div class="container">
<div class="header">
    <h1>⚡ Proxy Panel Scanner</h1>
    <p>اسکن از سرور پنل — تأخیر و Egress واقعی، مستقل از اینترنت تو</p>
</div>

<!-- نوار اطلاعات پنل -->
<div class="panelbar" id="panelBar">
    <span class="t">🖥 پنل:</span>
    <span class="pi" id="piIP">...</span>
    <span class="eg2"><span id="piFlag">❓</span><span id="piCountry">...</span></span>
    <span class="lbl2">پینگ پنل:</span>
    <span class="pg" id="piPing">...</span>
</div>

<div class="step">
    <div class="step-title"><span class="step-num">1</span> ورودی IP ها
        <span class="badge" style="margin-right:auto;">پورت‌ها: 1081 | 1082 | 1083 | 14111</span>
    </div>
    <div class="grid2">
        <div>
            <span class="lbl">IP دلخواه (IP یا IP:Port هر خط یکی)</span>
            <textarea id="customIps" placeholder="161.35.90.0/24&#10;161.35.90.93:1082&#10;45.12.33.7"></textarea>
        </div>
        <div>
            <span class="lbl">رنج خودکار (CIDR)</span>
            <input type="text" id="cidrInput" placeholder="161.35.90.0/24" style="margin-bottom:10px;">
            <div class="grid2" style="gap:8px;">
                <div>
                    <span class="lbl">Threads</span>
                    <input type="number" id="threadInput" value="200" min="1" max="500">
                </div>
                <div>
                    <span class="lbl">Timeout</span>
                    <select id="timeoutInput">
                        <option value="5">5s</option>
                        <option value="8" selected>8s</option>
                        <option value="12">12s</option>
                    </select>
                </div>
            </div>
        </div>
    </div>
    <button class="b-confirm" onclick="collectIPs()">✓ تایید و جمع‌آوری</button>
    <button class="b-test" onclick="runSelftest()">🧪 تست سلامت سرور پنل</button>
</div>

<div class="step" id="step2" style="display:none;">
    <div class="step-title"><span class="step-num">2</span> IP های تایید شده <span id="c2" class="badge">0</span></div>
    <div class="ip-list" id="ipList"></div>
    <div class="b-row">
        <button class="b-scan" id="scanBtn" onclick="startScan()">▶️ شروع اسکن</button>
        <button class="b-gray" onclick="resetAll()">🗑 شروع مجدد</button>
    </div>
</div>

<div class="step" id="step3" style="display:none;">
    <div class="step-title"><span class="step-num">3</span> پروکسی‌های سالم <span id="c3" class="badge">0</span></div>
    <div class="pbar"><div class="pfill" id="pfill"></div></div>
    <div class="ptext"><span id="ptxt" class="pulse">⏳ در حال اسکن...</span><span id="pdetail">0 / 0</span></div>
    <div class="stats">
        <div class="stat c"><div class="n" id="sDone">0</div><div class="l">بررسی شده</div></div>
        <div class="stat y"><div class="n" id="sOpen">0</div><div class="l">پورت باز</div></div>
        <div class="stat g"><div class="n" id="sAlive">0</div><div class="l">پروکسی سالم</div></div>
        <div class="stat r"><div class="n" id="sFail">0</div><div class="l">پورت باز، پروکسی نه</div></div>
    </div>
    <div class="diag" id="diag"></div>

    <div class="toolbar" id="toolbar" style="display:none;">
        <span class="chipbtn on" id="f-all" onclick="setFilter('all')">همه</span>
        <span class="chipbtn" id="f-socks" onclick="setFilter('socks')">SOCKS</span>
        <span class="chipbtn" id="f-http" onclick="setFilter('http')">HTTP</span>
        <span class="chipbtn" id="f-lat" onclick="toggleSort()">⏱ تأخیر</span>
        <button class="b-gray" style="padding:8px 16px;font-size:.8em;" onclick="retestAll()">🔄 تست مجدد همه</button>
    </div>

    <div class="b-row">
        <button class="b-copy" onclick="copyResults()">📋 کپی</button>
        <button class="b-dl" onclick="downloadTxt()">⬇️ TXT</button>
        <button class="b-dl" onclick="downloadJson()">⬇️ JSON</button>
        <button class="b-gray" onclick="clearResults()">🗑 پاک کردن</button>
    </div>

    <div class="cards" id="cards">
        <div class="empty" id="emptyState"><div class="ic">🔍</div><p>هنوز پروکسی‌ای پیدا نشده</p></div>
    </div>
</div>
</div>
<div class="toast" id="toast"></div>

<script>
var pollTimer = null, curFilter = 'all', sortLat = false, cacheResults = [];

function loadPanelInfo() {
    fetch('/api/panel_info').then(function(r){ return r.json(); }).then(function(d){
        document.getElementById('panelBar').style.display = 'flex';
        document.getElementById('piIP').textContent = d.ip;
        document.getElementById('piFlag').textContent = d.flag;
        document.getElementById('piCountry').textContent = d.country_fa;
        var pg = document.getElementById('piPing');
        if (d.ping > 0) {
            pg.textContent = '✓ ' + d.ping + ' ms';
            pg.className = 'pg' + (d.ping < 200 ? '' : (d.ping < 500 ? ' mid' : ''));
        } else {
            pg.textContent = '✗ قطع';
            pg.className = 'pg mid';
        }
    });
}

function collectIPs() {
    var cu = document.getElementById('customIps').value;
    var ci = document.getElementById('cidrInput').value;
    if (!cu.trim() && !ci.trim()) { showToast('حداقل یک ورودی پر کن!'); return; }
    fetch('/api/collect', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({custom:cu, cidr:ci})})
    .then(function(r){ return r.json(); })
    .then(function(d){
        if (d.error) { showToast('❌ ' + d.error); return; }
        if (!d.pairs || !d.pairs.length) { showToast('هیچ IP معتبری نبود!'); return; }
        document.getElementById('step2').style.display = 'block';
        document.getElementById('c2').textContent = d.pairs.length + ' IP';
        var items = [];
        for (var i=0;i<d.pairs.length;i++) {
            items.push(d.pairs[i][0] + (d.pairs[i][1] ? ':'+d.pairs[i][1] : ''));
        }
        document.getElementById('ipList').textContent = items.slice(0,500).join('\\n') +
            (items.length>500 ? '\\n... و ' + (items.length-500) + ' IP دیگر' : '');
        document.getElementById('step2').scrollIntoView({behavior:'smooth'});
        showToast('✅ ' + d.pairs.length + ' IP آماده');
    }).catch(function(){ showToast('خطا در اتصال'); });
}

function runSelftest() {
    showToast('🧪 در حال تست سرور...');
    fetch('/api/selftest', {method:'POST'})
    .then(function(r){ return r.json(); })
    .then(function(d){
        var ok=0, msg='تست سرور پنل:\\n\\n';
        for (var i=0;i<d.results.length;i++) {
            var x=d.results[i]; msg += x.target+' → '+x.note+'\\n'; if(x.ok) ok++;
        }
        if (ok===0) msg += '\\n❌ سرور به اینترنت وصل نیست!';
        else msg += '\\n✅ سرور پنل سالمه ('+ok+'/'+d.results.length+')';
        alert(msg);
    });
}

function startScan() {
    fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
            threads: parseInt(document.getElementById('threadInput').value)||200,
            timeout: parseInt(document.getElementById('timeoutInput').value)||8
        })})
    .then(function(r){ return r.json(); })
    .then(function(d){
        if (d.status!=='started') { showToast('شروع نشد: '+d.status); return; }
        document.getElementById('step3').style.display='block';
        document.getElementById('scanBtn').disabled=true;
        document.getElementById('ptxt').textContent='⏳ در حال اسکن از سرور...';
        document.getElementById('ptxt').classList.add('pulse');
        document.getElementById('diag').className='diag';
        document.getElementById('step3').scrollIntoView({behavior:'smooth'});
        pollTimer = setInterval(pollStatus, 1000);
    });
}

function pollStatus() {
    fetch('/api/status').then(function(r){ return r.json(); }).then(function(d){
        document.getElementById('sDone').textContent=d.done;
        document.getElementById('sOpen').textContent=d.opened;
        document.getElementById('sAlive').textContent=d.alive;
        document.getElementById('sFail').textContent=d.http_fail;
        document.getElementById('pdetail').textContent=d.done+' / '+d.total;
        document.getElementById('c3').textContent=d.alive;
        document.getElementById('pfill').style.width=(d.total>0?(d.done/d.total*100):0)+'%';
        loadResults();
        if (!d.running && d.done>0) {
            clearInterval(pollTimer);
            document.getElementById('scanBtn').disabled=false;
            document.getElementById('ptxt').textContent='✅ تمام شد';
            document.getElementById('ptxt').classList.remove('pulse');
            diagnose(d);
        }
    });
}

function diagnose(d) {
    var b=document.getElementById('diag');
    if (d.alive>0) { b.className='diag good'; b.innerHTML='🎉 '+d.alive+' پروکسی سالم پیدا شد!'; }
    else if (d.opened===0) { b.className='diag warn';
        b.innerHTML='هیچ پورتی باز نبود. رنج دیگه امتحان کن.'; }
    else { b.className='diag warn';
        b.innerHTML=d.opened+' پورت باز بود ولی پروکسی واقعی نبودن.'; }
}

function loadResults() {
    fetch('/api/results').then(function(r){ return r.json(); }).then(function(d){
        cacheResults = d.results || [];
        renderCards();
        var tb=document.getElementById('toolbar');
        if (cacheResults.length>0) tb.style.display='flex';
    });
}

function setFilter(f) {
    curFilter=f;
    ['all','socks','http'].forEach(function(x){
        document.getElementById('f-'+x).className = (x===f?'chipbtn on':'chipbtn');
    });
    renderCards();
}
function toggleSort() {
    sortLat=!sortLat;
    document.getElementById('f-lat').className='chipbtn'+(sortLat?' on':'');
    renderCards();
}
function latClass(ms) { return ms<400?'':(ms<900?' mid':' bad'); }

function renderCards() {
    var box=document.getElementById('cards');
    var list=cacheResults.filter(function(r){
        if (curFilter==='all') return true;
        return r.proto===curFilter;
    });
    if (sortLat) list=list.slice().sort(function(a,b){ return a.latency-b.latency; });
    document.getElementById('c3').textContent=list.length;

    if (!list.length) {
        box.innerHTML='<div class="empty"><div class="ic">🔍</div><p>'+
            (cacheResults.length? 'این فیلتر نتیجه‌ای نداره' : 'هنوز پروکسی‌ای پیدا نشده')+'</p></div>';
        return;
    }
    var h='';
    for (var i=0;i<list.length;i++) {
        var r=list[i];
        h += '<div class="pcard">'
          + '<div class="pcard-top">'
          + '<span class="idx">'+(i+1)+'</span>'
          + '<span class="proto '+r.proto+'">'+r.proto+'</span>'
          + '<span class="lat'+latClass(r.latency)+'">✓ '+r.latency+' ms</span>'
          + '</div>'
          + '<span class="chipip">'+r.ip+':'+r.port+'</span>'
          + '<div class="prow"><span class="k">Egress:</span>'
          + '<span class="eg"><span class="f">'+r.flag+'</span>'+r.country_fa+'</span></div>'
          + '<div class="prow"><span class="k">V4:</span><span class="v4">'+(r.exit_ip||'—')+'</span></div>'
          + '<div class="prow"><span class="k">ISP:</span><span>'+r.isp+'</span></div>'
          + '<div class="pbottom"><span class="traffic">↑ 0 B &nbsp; ↓ 0 B</span>'
          + '<button class="bolt" onclick="retestOne(\\''+r.ip+'\\','+r.port+',this)">⚡</button>'
          + '</div></div>';
    }
    box.innerHTML=h;
}

function retestOne(ip, port, btn) {
    btn.disabled=true;
    fetch('/api/retest_one', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ip:ip, port:port})})
    .then(function(r){ return r.json(); })
    .then(function(d){
        if (d.removed) showToast('❌ دیگه جواب نمیده');
        else showToast('⚡ '+d.latency+' ms');
        loadResults();
    });
}

function retestAll() {
    if (!cacheResults.length) { showToast('چیزی برای تست نیست'); return; }
    showToast('🔄 تست مجدد شروع شد...');
    fetch('/api/retest', {method:'POST'}).then(function(r){ return r.json(); }).then(function(d){
        if (d.status==='started') {
            document.getElementById('ptxt').textContent='⏳ در حال تست مجدد...';
            document.getElementById('ptxt').classList.add('pulse');
            pollTimer=setInterval(pollStatus,1000);
        }
    });
}

function copyResults() {
    fetch('/api/results/text').then(function(r){ return r.text(); }).then(function(t){
        if (navigator.clipboard&&navigator.clipboard.writeText) {
            navigator.clipboard.writeText(t).then(function(){ showToast('📋 کپی شد!'); })
            .catch(function(){ fbCopy(t); });
        } else fbCopy(t);
    });
}
function fbCopy(t) {
    var a=document.createElement('textarea'); a.value=t;
    document.body.appendChild(a); a.select();
    document.execCommand('copy'); document.body.removeChild(a);
    showToast('📋 کپی شد!');
}
function downloadTxt(){ window.open('/api/download/txt'); }
function downloadJson(){ window.open('/api/download/json'); }

function clearResults() {
    fetch('/api/clear',{method:'POST'}).then(function(){
        cacheResults=[]; renderCards();
        document.getElementById('toolbar').style.display='none';
        ['sDone','sOpen','sAlive','sFail'].forEach(function(id){
            document.getElementById(id).textContent='0'; });
        document.getElementById('diag').className='diag';
        showToast('🗑 پاک شد');
    });
}
function resetAll() {
    fetch('/api/reset',{method:'POST'}).then(function(){
        document.getElementById('step2').style.display='none';
        document.getElementById('step3').style.display='none';
        document.getElementById('customIps').value='';
        document.getElementById('cidrInput').value='';
        cacheResults=[]; clearInterval(pollTimer);
        showToast('🔄 ریست شد');
    });
}
function showToast(m) {
    var t=document.getElementById('toast');
    t.textContent=m; t.style.display='block';
    setTimeout(function(){ t.style.display='none'; },2500);
}

window.onload=function(){
    loadPanelInfo();
    fetch('/api/results').then(function(r){ return r.json(); }).then(function(d){
        if (d.results && d.results.length) {
            document.getElementById('step3').style.display='block';
            cacheResults=d.results; renderCards();
            document.getElementById('toolbar').style.display='flex';
        }
    });
};
</script>
</body>
</html>
"""


# ================= وب‌سرور =================
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype, extra=None):
        data = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _json(self, obj, code=200, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   'application/json; charset=utf-8', extra)

    def do_GET(self):
        p = self.path.split('?')[0]
        if p == '/':
            self._send(200, HTML, 'text/html; charset=utf-8')
        elif p == '/api/panel_info':
            self._json(get_panel_info())
        elif p == '/api/status':
            with lock:
                self._json({k: state[k] for k in
                            ('running', 'total', 'done', 'alive',
                             'opened', 'closed', 'http_fail')})
        elif p == '/api/results':
            self._json({'results': sorted_results()})
        elif p == '/api/results/text':
            self._send(200, build_text(), 'text/plain; charset=utf-8')
        elif p == '/api/download/txt':
            self._send(200, build_text(True), 'text/plain; charset=utf-8',
                       {'Content-Disposition': f'attachment; filename="proxies_{stamp()}.txt"'})
        elif p == '/api/download/json':
            self._send(200, json.dumps(sorted_results(), ensure_ascii=False, indent=2),
                       'application/json; charset=utf-8',
                       {'Content-Disposition': f'attachment; filename="proxies_{stamp()}.json"'})
        else:
            self._json({'error': 'not found'}, 404)

    def do_POST(self):
        p = self.path.split('?')[0]
        n = int(self.headers.get('Content-Length', 0) or 0)
        body = {}
        if n:
            try:
                body = json.loads(self.rfile.read(n).decode('utf-8'))
            except Exception:
                body = {}

        if p == '/api/collect':
            pairs, err = collect_pairs(body.get('custom', ''), body.get('cidr', ''))
            if err:
                self._json({'error': err})
                return
            with lock:
                state['collected_pairs'] = pairs
            self._json({'pairs': pairs})

        elif p == '/api/scan':
            if state['running']:
                self._json({'status': 'already_running'})
                return
            with lock:
                if not state['collected_pairs']:
                    self._json({'status': 'no_ips'})
                    return
            cfg['port_timeout'] = max(2, int(body.get('timeout', 8) or 8) - 3)
            cfg['proxy_timeout'] = max(4, int(body.get('timeout', 8) or 8))
            threads = max(1, min(500, int(body.get('threads', 200) or 200)))
            threading.Thread(target=run_scan, args=(threads,), daemon=True).start()
            self._json({'status': 'started'})

        elif p == '/api/retest':
            if state['running']:
                self._json({'status': 'already_running'})
                return
            threading.Thread(target=run_retest, daemon=True).start()
            self._json({'status': 'started'})

        elif p == '/api/retest_one':
            ip, port = body.get('ip'), int(body.get('port', 0))
            with lock:
                target = next((r for r in state['scan_results']
                               if r['ip'] == ip and r['port'] == port), None)
            if not target:
                self._json({'removed': True})
                return
            retest_one(target)
            with lock:
                still = next((r for r in state['scan_results']
                              if r['ip'] == ip and r['port'] == port), None)
            if still:
                self._json({'latency': still['latency']})
            else:
                self._json({'removed': True})

        elif p == '/api/selftest':
            self._json({'results': run_selftest()})

        elif p == '/api/clear':
            with lock:
                state['scan_results'] = []
                state['total'] = state['done'] = state['alive'] = 0
                state['opened'] = state['closed'] = state['http_fail'] = 0
            self._json({'status': 'cleared'})

        elif p == '/api/reset':
            with lock:
                state.update(collected_pairs=[], scan_results=[], running=False,
                             stop_flag=False, total=0, done=0, alive=0,
                             opened=0, closed=0, http_fail=0)
            self._json({'status': 'reset'})

        else:
            self._json({'error': 'not found'}, 404)


def main():
    try:
        server = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
        server.daemon_threads = True
    except OSError:
        print(f"\n❌ پورت {PORT} اشغاله!\n")
        return

    print("""
    ╔════════════════════════════════════════════════════╗
    ║   ⚡ PROXY PANEL SCANNER v7 — آنلاین ⚡             ║
    ╠════════════════════════════════════════════════════╣
    ║  پورت‌های اسکن:  1081 | 1082 | 1083 | 14111        ║
    ║  تشخیص: SOCKS5 / SOCKS4 / HTTP                     ║
    ║  Egress + پرچم + پینگ واقعی پنل                    ║
    ║                                                    ║
    ║  ➜  http://127.0.0.1:%-27d ║
    ║                                                    ║
    ║  خروج: Ctrl+C                                      ║
    ╚════════════════════════════════════════════════════╝
    """ % PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] بسته شد")


if __name__ == '__main__':
    main()