#!/usr/bin/env python3
"""
JackalRouter — Control Panel (Windows, Tkinter)
Features: proxy apply, proxy check + geo, UDP check, EN/RU language, proxy history.
"""

import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
import re
import socket
import struct
import json
import os
import time
from datetime import datetime
from urllib.parse import quote

try:
    import requests
    requests.get
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests[socks]"])
    import requests

try:
    import socks  # PySocks — needed for SOCKS5 support in requests
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "PySocks"])

SERVER_PORT  = 8000
TIMEOUT      = 15
HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_history.json")

GEO_URLS = [
    "http://ip-api.com/json?fields=status,country,countryCode,regionName,city,isp,query",
    "http://ip-api.com/json",
    "http://ipinfo.io/json",
]

# Открытый источник для проверки «чистоты»: ip-api.com отдаёт security-флаги
# proxy / hosting / mobile бесплатно (для некоммерческого использования).
CLEAN_URL = ("http://ip-api.com/json/?fields=status,message,country,countryCode,"
             "regionName,city,isp,org,as,query,proxy,hosting,mobile,reverse")
# Cloudflare speed endpoint — отдаёт N байт мусора, считаем пропускную способность.
SPEED_URL   = "https://speed.cloudflare.com/__down?bytes={bytes}"
SPEED_BYTES = 3_000_000          # 3 МБ — достаточно для оценки, не слишком долго
SPEED_TIMEOUT = 30


def socks5_ping(host: str, port: int, user: str, password: str,
                dest: str = "google.com", dest_port: int = 80,
                timeout: int = 10) -> tuple:
    """Raw SOCKS5 handshake — проверяет доступность и авторизацию без HTTP."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        has_auth = bool(user and password)
        methods = b"\x02" if has_auth else b"\x00"
        s.sendall(b"\x05" + bytes([len(methods)]) + methods)
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 5:
            s.close(); return False, "invalid SOCKS5 response"
        if resp[1] == 0xFF:
            s.close(); return False, "proxy refused auth methods"
        if resp[1] == 2:
            u, p = user.encode(), password.encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            resp = s.recv(2)
            if len(resp) < 2 or resp[1] != 0:
                s.close(); return False, "authentication failed (wrong login/password)"
        d = dest.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d
                  + dest_port.to_bytes(2, "big"))
        resp = s.recv(10)
        s.close()
        if len(resp) < 2:
            return False, "no CONNECT response"
        if resp[1] != 0:
            codes = {1: "server error", 2: "rules forbidden", 3: "network unreachable",
                    4: "host unreachable", 5: "connection refused"}
            return False, f"CONNECT error: {codes.get(resp[1], f'code {resp[1]}')}"
        return True, "ok"
    except socket.timeout:
        return False, f"timeout {timeout}s"
    except ConnectionRefusedError:
        return False, "connection refused"
    except OSError as e:
        return False, str(e)


def socks5_udp_check(host: str, port: int, user: str, password: str,
                     timeout: int = 10) -> tuple:
    """Проверяет поддержку UDP ASSOCIATE у прокси."""
    t = u = None
    try:
        t = socket.create_connection((host, port), timeout=timeout)
        t.settimeout(timeout)
        has_auth = bool(user and password)
        methods = b"\x02" if has_auth else b"\x00"
        t.sendall(b"\x05" + bytes([len(methods)]) + methods)
        resp = t.recv(2)
        if len(resp) < 2 or resp[0] != 5:
            return False, "invalid SOCKS5 response"
        if resp[1] == 0xFF:
            return False, "proxy refused auth methods"
        if resp[1] == 2:
            uu, pp = user.encode(), password.encode()
            t.sendall(b"\x01" + bytes([len(uu)]) + uu + bytes([len(pp)]) + pp)
            resp = t.recv(2)
            if len(resp) < 2 or resp[1] != 0:
                return False, "authentication failed (wrong login/password)"
        t.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        resp = t.recv(10)
        if len(resp) < 10 or resp[1] != 0:
            return False, "UDP ASSOCIATE rejected by proxy"
        bnd_ip = socket.inet_ntoa(resp[4:8])
        bnd_port = struct.unpack("!H", resp[8:10])[0]
        if bnd_ip in ("0.0.0.0", "127.0.0.1"):
            bnd_ip = host
        dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for part in b"example.com".split(b"."):
            dns += bytes([len(part)]) + part
        dns += b"\x00\x00\x01\x00\x01"
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") \
            + struct.pack("!H", 53) + dns
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(timeout)
        u.sendto(pkt, (bnd_ip, bnd_port))
        data, _ = u.recvfrom(2048)
        if len(data) > 10:
            return True, "ok"
        return False, "empty UDP response"
    except socket.timeout:
        return False, "UDP relay timeout (associate granted, no forwarding)"
    except ConnectionRefusedError:
        return False, "connection refused"
    except OSError as e:
        return False, str(e)
    finally:
        for sk in (u, t):
            try:
                if sk:
                    sk.close()
            except Exception:
                pass


def measure_speed(proxies: dict) -> tuple:
    """Качает SPEED_BYTES через прокси, возвращает (mbps, kb_per_s, latency_ms)
    или (None, None, None) при ошибке."""
    url = SPEED_URL.format(bytes=SPEED_BYTES)
    try:
        t0 = time.time()
        r = requests.get(url, proxies=proxies, timeout=SPEED_TIMEOUT, stream=True)
        r.raise_for_status()
        total = 0
        first_byte_at = None
        for chunk in r.iter_content(65536):
            if not chunk:
                continue
            if first_byte_at is None:
                first_byte_at = time.time()
            total += len(chunk)
        dt = time.time() - t0
        if total <= 0 or dt <= 0:
            return None, None, None
        bytes_per_s = total / dt
        kb_per_s    = bytes_per_s / 1024
        mbps        = bytes_per_s * 8 / 1_000_000
        latency_ms  = int((first_byte_at - t0) * 1000) if first_byte_at else None
        return mbps, kb_per_s, latency_ms
    except Exception:
        return None, None, None


# ── Строки интерфейса ─────────────────────────────────────────────────────────

S = {
    "ru": {
        "title":          "JackalRouter — Пульт управления",
        "subtitle":       "Управление прокси-маршрутизацией",
        "cur_label":      "Раздаётся:",
        "cur_none":       "— нажмите ⟳ или «Проверить сервер»",
        "cur_loading":    "запрашиваю через активный прокси…",
        "cur_fmt":        "{}  |  {}  |  {}",
        "cur_err":        "не удалось определить ({})",
        "cur_no_proxy":   "прокси не задан — нажмите Route",
        "cur_partial":    "{} активен (вставьте этот прокси в поле для гео)",
        "ip_label":       "IP Ubuntu:",
        "proxy_label":    "Прокси:",
        "hint":           "Формат: ip:port:user:pass  или  user:pass@ip:port",
        "btn_apply":      "  Route  ",
        "btn_check":      "⬡  Проверить прокси",
        "btn_udp":        "⬡  Проверить UDP",
        "btn_server":     "⬡  Проверить сервер",
        "log_header":     "Лог:",
        "ready":          "Готов к работе",
        "sending":        "Отправка на Ubuntu…",
        "checking":       "Проверяю прокси…",
        "srv_checking":   "Проверяю сервер…",
        "err_no_ip":      "Укажите IP-адрес Ubuntu.",
        "err_no_proxy":   "Вставьте строку прокси.",
        "err_format":     "Неверный формат: {}",
        "err_format2":    "Ожидается:  ip:port:user:pass  или  user:pass@ip:port",
        "log_sending":    "→  POST http://{}:{}/set_proxy",
        "log_ok":         "Прокси применён. Роутер раздаёт американский интернет [{}]",
        "log_conn_err":   "Нет связи с {}:{}. Проверьте IP и что сервер запущен.",
        "log_timeout":    "Таймаут {}с — Ubuntu не отвечает.",
        "log_http_err":   "Ошибка сервера {}: {}",
        "log_unk_err":    "Неожиданная ошибка: {}",
        "st_ok":          "Прокси применён ✓",
        "st_err":         "Ошибка",
        "chk_start":      "Проверяю прокси через {}:{} …",
        "chk_ok":         "✓ Рабочий  |  IP: {}  |  {}, {}  |  {}",
        "chk_warn":       "⚠ Работает, но НЕ США: {} ({}, {})",
        "chk_fail":       "✗ Прокси недоступен: {}",
        "chk_st_ok":      "Прокси работает ✓",
        "chk_st_warn":    "Не США ⚠",
        "chk_st_fail":    "Прокси не работает ✗",
        "udp_checking":   "Проверяю UDP…",
        "udp_start":      "Проверяю UDP ASSOCIATE через {}:{} …",
        "udp_ok":         "✓ UDP работает  |  прокси поддерживает UDP ASSOCIATE — QUIC пойдёт через прокси",
        "udp_fail":       "✗ UDP не поддерживается: {}",
        "udp_note":       "   › QUIC будет заблокирован (DROP). Это повышает fraud-score антидетектов.",
        "udp_st_ok":      "UDP работает ✓",
        "udp_st_fail":    "UDP не работает ✗",
        "btn_clean":      "⬡  Проверить чистоту",
        "clean_checking": "Проверяю чистоту и скорость…",
        "clean_start":    "Проверяю чистоту/скорость через {}:{} …",
        "clean_geo":      "   IP: {}  |  {}, {}  |  {}",
        "clean_dirty":    "✗ ГРЯЗНЫЙ — IP помечен как proxy/VPN/Tor в открытых базах",
        "clean_host":     "⚠ Datacenter/Hosting — не резидент, ↑ fraud-score антидетектов",
        "clean_ok":       "✓ ЧИСТЫЙ — резидентный IP (не proxy, не hosting)",
        "clean_flags":    "   Флаги:  proxy={}  hosting={}  mobile={}",
        "clean_rdns":     "   rDNS:  {}",
        "clean_speed":    "   Скорость: {}  |  задержка {} мс",
        "clean_speed_na": "   Скорость: измерить не удалось",
        "clean_geo_na":   "   Репутация недоступна (открытый источник не ответил через прокси)",
        "clean_st_ok":    "Чистый ✓",
        "clean_st_warn":  "Datacenter ⚠",
        "clean_st_fail":  "Грязный ✗",
        "srv_up":         "✓  JackalRouter отвечает",
        "srv_warn":       "⚠  Сервер отвечает — есть проблемы",
        "srv_down":       "✗  Сервер не отвечает на {}:{}",
        "srv_hint":       "   → sudo systemctl start jackalrouter",
        "srv_no_proxy":   "   › Прокси не задан — нажмите Route",
        "srv_proxy":      "   › Прокси: {}",
        "srv_ipt_ok":     "настроена",
        "srv_ipt_err":    "НЕ настроена",
        "srv_desc_sb":    "TCP/UDP → sing-box → SOCKS5",
        "srv_desc_dns":   "DHCP-сервер / DNS",
        "srv_st_ok":      "Сервер ✓",
        "srv_st_warn":    "Сервер ⚠",
        "srv_st_down":    "Сервер недоступен ✗",
        # История
        "tab_main":       "Управление",
        "tab_history":    "История",
        "hist_col_proxy": "Прокси",
        "hist_col_geo":   "Страна / Город",
        "hist_col_isp":   "ISP",
        "hist_col_date":  "Когда",
        "hist_col_st":    "Ст.",
        "hist_load":      "⇥  Загрузить",
        "hist_check":     "⬡  Проверить",
        "hist_delete":    "✕  Удалить",
        "hist_nosel":     "Выберите прокси в таблице",
        "hist_dblclick":  "Двойной клик — загрузить прокси в поле выше",
        "hist_loaded":    "Загружен из истории: {}",
        "hist_checking":  "Проверяю прокси из истории…",
    },
    "en": {
        "title":          "JackalRouter — Control Panel",
        "subtitle":       "Proxy routing management",
        "cur_label":      "Broadcasting:",
        "cur_none":       "— click ⟳ or “Check server”",
        "cur_loading":    "querying via active proxy…",
        "cur_fmt":        "{}  |  {}  |  {}",
        "cur_err":        "could not determine ({})",
        "cur_no_proxy":   "no proxy set — click Route",
        "cur_partial":    "{} active (paste this proxy into the field for geo)",
        "ip_label":       "Ubuntu IP:",
        "proxy_label":    "Proxy:",
        "hint":           "Format: ip:port:user:pass  or  user:pass@ip:port",
        "btn_apply":      "  Route  ",
        "btn_check":      "⬡  Check proxy",
        "btn_udp":        "⬡  Check UDP",
        "btn_server":     "⬡  Check server",
        "log_header":     "Log:",
        "ready":          "Ready",
        "sending":        "Sending to Ubuntu…",
        "checking":       "Checking proxy…",
        "srv_checking":   "Checking server…",
        "err_no_ip":      "Enter Ubuntu IP address.",
        "err_no_proxy":   "Paste proxy string.",
        "err_format":     "Invalid format: {}",
        "err_format2":    "Expected:  ip:port:user:pass  or  user:pass@ip:port",
        "log_sending":    "→  POST http://{}:{}/set_proxy",
        "log_ok":         "Proxy applied. Router is broadcasting US internet [{}]",
        "log_conn_err":   "Cannot connect to {}:{}. Check IP and server status.",
        "log_timeout":    "Timeout {}s — Ubuntu not responding.",
        "log_http_err":   "Server error {}: {}",
        "log_unk_err":    "Unexpected error: {}",
        "st_ok":          "Proxy applied ✓",
        "st_err":         "Error",
        "chk_start":      "Checking proxy via {}:{} …",
        "chk_ok":         "✓ Working  |  IP: {}  |  {}, {}  |  {}",
        "chk_warn":       "⚠ Works but NOT US: {} ({}, {})",
        "chk_fail":       "✗ Proxy unreachable: {}",
        "chk_st_ok":      "Proxy works ✓",
        "chk_st_warn":    "Not US ⚠",
        "chk_st_fail":    "Proxy failed ✗",
        "udp_checking":   "Checking UDP…",
        "udp_start":      "Checking UDP ASSOCIATE via {}:{} …",
        "udp_ok":         "✓ UDP works  |  proxy supports UDP ASSOCIATE — QUIC will go through proxy",
        "udp_fail":       "✗ UDP not supported: {}",
        "udp_note":       "   › QUIC will be blocked (DROP). This raises antidetect fraud-score.",
        "udp_st_ok":      "UDP works ✓",
        "udp_st_fail":    "UDP failed ✗",
        "btn_clean":      "⬡  Check cleanliness",
        "clean_checking": "Checking cleanliness & speed…",
        "clean_start":    "Checking cleanliness/speed via {}:{} …",
        "clean_geo":      "   IP: {}  |  {}, {}  |  {}",
        "clean_dirty":    "✗ DIRTY — IP flagged as proxy/VPN/Tor in open databases",
        "clean_host":     "⚠ Datacenter/Hosting — not residential, ↑ antidetect fraud-score",
        "clean_ok":       "✓ CLEAN — residential IP (not proxy, not hosting)",
        "clean_flags":    "   Flags:  proxy={}  hosting={}  mobile={}",
        "clean_rdns":     "   rDNS:  {}",
        "clean_speed":    "   Speed: {}  |  latency {} ms",
        "clean_speed_na": "   Speed: measurement failed",
        "clean_geo_na":   "   Reputation unavailable (open source did not respond via proxy)",
        "clean_st_ok":    "Clean ✓",
        "clean_st_warn":  "Datacenter ⚠",
        "clean_st_fail":  "Dirty ✗",
        "srv_up":         "✓  JackalRouter is running",
        "srv_warn":       "⚠  Server responds — issues found",
        "srv_down":       "✗  Server not responding at {}:{}",
        "srv_hint":       "   → sudo systemctl start jackalrouter",
        "srv_no_proxy":   "   › No proxy set — click Route",
        "srv_proxy":      "   › Proxy: {}",
        "srv_ipt_ok":     "configured",
        "srv_ipt_err":    "NOT configured",
        "srv_desc_sb":    "TCP/UDP → sing-box → SOCKS5",
        "srv_desc_dns":   "DHCP server / DNS",
        "srv_st_ok":      "Server ✓",
        "srv_st_warn":    "Server ⚠",
        "srv_st_down":    "Server unreachable ✗",
        # History
        "tab_main":       "Control",
        "tab_history":    "History",
        "hist_col_proxy": "Proxy",
        "hist_col_geo":   "Country / City",
        "hist_col_isp":   "ISP",
        "hist_col_date":  "When",
        "hist_col_st":    "St.",
        "hist_load":      "⇥  Load",
        "hist_check":     "⬡  Check",
        "hist_delete":    "✕  Delete",
        "hist_nosel":     "Select a proxy in the table",
        "hist_dblclick":  "Double-click to load proxy into the field above",
        "hist_loaded":    "Loaded from history: {}",
        "hist_checking":  "Checking proxy from history…",
    },
}

# ── Парсинг прокси ────────────────────────────────────────────────────────────

def parse_proxy(s: str):
    """Returns dict(ip, port, user, password) or None."""
    s = s.strip()
    s = re.sub(r'^[a-zA-Z0-9+.\-]+://', '', s)
    m = re.match(r'^([^:@]+):(.+)@([\d.]+):(\d+)$', s)
    if m:
        return {"user": m.group(1), "password": m.group(2),
                "ip": m.group(3), "port": int(m.group(4))}
    parts = s.split(":", 3)
    if len(parts) == 4 and re.match(r'^\d{1,5}$', parts[1]):
        return {"ip": parts[0], "port": int(parts[1]),
                "user": parts[2], "password": parts[3]}
    return None


# ── Приложение ────────────────────────────────────────────────────────────────

class App:
    BG     = "#1e1e2e"
    PANEL  = "#181825"
    TEXT   = "#cdd6f4"
    MUTED  = "#6c7086"
    BLUE   = "#89b4fa"
    GREEN  = "#a6e3a1"
    RED    = "#f38ba8"
    YELLOW = "#f9e2af"
    SURF   = "#313244"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.lang = "ru"
        self.history = self._load_history()
        self._pending_proxy = ""
        root.geometry("740x570")
        root.resizable(True, True)
        root.minsize(700, 520)
        root.configure(bg=self.BG)
        self._build()
        self._apply_lang()

    # ── Построение UI ─────────────────────────────────────────────────────────

    def _build(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",
                        background=self.BG, borderwidth=0, tabmargins=0)
        style.configure("TNotebook.Tab",
                        background=self.SURF, foreground=self.MUTED,
                        font=("Segoe UI", 10), padding=[14, 5])
        style.map("TNotebook.Tab",
                  background=[("selected", self.PANEL)],
                  foreground=[("selected", self.BLUE)])
        style.configure("Hist.Treeview",
                        background=self.PANEL, foreground=self.TEXT,
                        fieldbackground=self.PANEL, rowheight=26,
                        font=("Consolas", 9), borderwidth=0)
        style.configure("Hist.Treeview.Heading",
                        background=self.SURF, foreground=self.BLUE,
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Hist.Treeview",
                  background=[("selected", self.BLUE)],
                  foreground=[("selected", self.BG)])
        style.configure("Hist.Vertical.TScrollbar",
                        background=self.SURF, troughcolor=self.PANEL,
                        arrowcolor=self.MUTED, borderwidth=0)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        self.tab_main = tk.Frame(self.notebook, bg=self.BG)
        self.tab_hist = tk.Frame(self.notebook, bg=self.BG)
        self.notebook.add(self.tab_main, text="Управление")
        self.notebook.add(self.tab_hist, text="История")

        self._build_main_tab()
        self._build_history_tab()

    def _build_main_tab(self):
        p = self.tab_main

        # ── Топ-бар: заголовок + переключатель языка ─────────────────────────
        top = tk.Frame(p, bg=self.BG)
        top.pack(fill="x", padx=16, pady=(14, 0))

        left = tk.Frame(top, bg=self.BG)
        left.pack(side="left", fill="x", expand=True)

        self.lbl_title = tk.Label(left, bg=self.BG, fg=self.BLUE,
                                  font=("Segoe UI", 16, "bold"))
        self.lbl_title.pack(anchor="w")
        self.lbl_subtitle = tk.Label(left, bg=self.BG, fg=self.MUTED,
                                     font=("Segoe UI", 9))
        self.lbl_subtitle.pack(anchor="w")

        lang_frame = tk.Frame(top, bg=self.BG)
        lang_frame.pack(side="right", anchor="n", pady=(4, 0))

        self.btn_ru = tk.Button(lang_frame, text="RU", width=3,
                                relief="flat", cursor="hand2",
                                font=("Segoe UI", 9, "bold"),
                                command=lambda: self._set_lang("ru"))
        self.btn_ru.pack(side="left")
        tk.Label(lang_frame, text="|", bg=self.BG, fg=self.MUTED).pack(side="left")
        self.btn_en = tk.Button(lang_frame, text="EN", width=3,
                                relief="flat", cursor="hand2",
                                font=("Segoe UI", 9, "bold"),
                                command=lambda: self._set_lang("en"))
        self.btn_en.pack(side="left")

        # ── Баннер «Сейчас раздаётся» (exit-IP активного прокси + гео) ───────
        cur = tk.Frame(p, bg=self.PANEL)
        cur.pack(fill="x", padx=16, pady=(12, 0))

        self.btn_cur = tk.Button(
            cur, text="⟳", width=3,
            bg=self.SURF, fg=self.TEXT,
            font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2",
            activebackground="#45475a", activeforeground=self.TEXT,
            command=self._on_refresh_current,
        )
        self.btn_cur.pack(side="right", padx=6, pady=5)

        self.lbl_cur_title = tk.Label(cur, bg=self.PANEL, fg=self.BLUE,
                                      font=("Segoe UI", 9, "bold"))
        self.lbl_cur_title.pack(side="left", padx=(10, 6), pady=6)

        self.lbl_cur_val = tk.Label(cur, bg=self.PANEL, fg=self.MUTED,
                                    font=("Segoe UI", 9), anchor="w", justify="left")
        self.lbl_cur_val.pack(side="left", pady=6, fill="x", expand=True)

        # ── IP Ubuntu ────────────────────────────────────────────────────────
        row1 = tk.Frame(p, bg=self.BG)
        row1.pack(fill="x", padx=16, pady=(14, 4))

        self.lbl_ip = tk.Label(row1, bg=self.BG, fg=self.TEXT,
                               font=("Segoe UI", 10), width=11, anchor="w")
        self.lbl_ip.pack(side="left")

        self.ip_var = tk.StringVar(value="192.168.1.96")
        self._entry(row1, self.ip_var, width=20).pack(side="left", padx=(4, 0))

        self.btn_server = tk.Button(
            row1, text="",
            bg=self.SURF, fg=self.TEXT,
            font=("Segoe UI", 9), relief="flat", cursor="hand2",
            activebackground="#45475a", activeforeground=self.TEXT,
            command=self._on_server_check,
        )
        self.btn_server.pack(side="left", padx=(10, 0))

        # ── Строка прокси ────────────────────────────────────────────────────
        row2 = tk.Frame(p, bg=self.BG)
        row2.pack(fill="x", padx=16, pady=4)

        self.lbl_proxy = tk.Label(row2, bg=self.BG, fg=self.TEXT,
                                  font=("Segoe UI", 10), width=11, anchor="w")
        self.lbl_proxy.pack(side="left")

        self.proxy_var = tk.StringVar()
        proxy_entry = self._entry(row2, self.proxy_var, width=55)
        proxy_entry.pack(side="left", padx=(4, 0), fill="x", expand=True)
        proxy_entry.focus()
        proxy_entry.bind("<Control-v>", self._paste_proxy)
        proxy_entry.bind("<Control-V>", self._paste_proxy)

        # ── Кнопки проверки прокси ────────────────────────────────────────────
        row3 = tk.Frame(p, bg=self.BG)
        row3.pack(fill="x", padx=16, pady=(2, 2))

        self.btn_check = tk.Button(
            row3, text="", width=18,
            bg=self.SURF, fg=self.TEXT,
            font=("Segoe UI", 9), relief="flat", cursor="hand2",
            activebackground="#45475a", activeforeground=self.TEXT,
            command=self._on_check,
        )
        self.btn_check.pack(side="left")

        self.btn_udp = tk.Button(
            row3, text="", width=18,
            bg=self.SURF, fg=self.TEXT,
            font=("Segoe UI", 9), relief="flat", cursor="hand2",
            activebackground="#45475a", activeforeground=self.TEXT,
            command=self._on_udp_check,
        )
        self.btn_udp.pack(side="left", padx=(8, 0))

        # Кнопка «Проверить чистоту» (репутация через открытые базы + скорость)
        self.btn_clean = tk.Button(
            row3, text="", width=20,
            bg=self.SURF, fg=self.TEXT,
            font=("Segoe UI", 9), relief="flat", cursor="hand2",
            activebackground="#45475a", activeforeground=self.TEXT,
            command=self._on_clean_check,
        )
        self.btn_clean.pack(side="left", padx=(8, 0))

        # ── Хинт формата ─────────────────────────────────────────────────────
        row3b = tk.Frame(p, bg=self.BG)
        row3b.pack(fill="x", padx=16, pady=(0, 6))

        self.lbl_hint = tk.Label(row3b, bg=self.BG, fg=self.MUTED,
                                 font=("Segoe UI", 8))
        self.lbl_hint.pack(side="left")

        # ── Кнопка «Route» ───────────────────────────────────────────────────
        self.btn_apply = tk.Button(
            p, text="",
            bg=self.BLUE, fg=self.BG,
            font=("Segoe UI", 11, "bold"),
            relief="flat", cursor="hand2",
            activebackground="#74c7ec", activeforeground=self.BG,
            command=self._on_apply, padx=10, pady=7,
        )
        self.btn_apply.pack(pady=(4, 6))

        # ── Статус ───────────────────────────────────────────────────────────
        self.status_var = tk.StringVar()
        self.status_lbl = tk.Label(
            p, textvariable=self.status_var,
            bg=self.BG, fg=self.TEXT, font=("Segoe UI", 10, "bold")
        )
        self.status_lbl.pack()

        # ── Лог ──────────────────────────────────────────────────────────────
        log_frame = tk.Frame(p, bg=self.BG)
        log_frame.pack(fill="both", expand=True, padx=16, pady=(6, 14))

        self.lbl_log = tk.Label(log_frame, bg=self.BG, fg=self.MUTED,
                                font=("Segoe UI", 8))
        self.lbl_log.pack(anchor="w")

        self.log = scrolledtext.ScrolledText(
            log_frame, bg=self.PANEL, fg=self.TEXT,
            font=("Consolas", 9), insertbackground=self.TEXT,
            state="disabled", relief="flat",
        )
        self.log.pack(fill="both", expand=True)
        self.log.tag_config("ok",   foreground=self.GREEN)
        self.log.tag_config("err",  foreground=self.RED)
        self.log.tag_config("info", foreground=self.BLUE)
        self.log.tag_config("warn", foreground=self.YELLOW)

    def _build_history_tab(self):
        p = self.tab_hist

        # ── Таблица ───────────────────────────────────────────────────────────
        tree_frame = tk.Frame(p, bg=self.BG)
        tree_frame.pack(fill="both", expand=True, padx=12, pady=(10, 4))

        sb = ttk.Scrollbar(tree_frame, orient="vertical",
                           style="Hist.Vertical.TScrollbar")
        self.hist_tree = ttk.Treeview(
            tree_frame,
            style="Hist.Treeview",
            columns=("server", "geo", "isp", "date", "status"),
            show="headings",
            selectmode="browse",
            yscrollcommand=sb.set,
        )
        sb.config(command=self.hist_tree.yview)
        sb.pack(side="right", fill="y")
        self.hist_tree.pack(fill="both", expand=True)

        self.hist_tree.column("server", width=160, minwidth=120, anchor="w")
        self.hist_tree.column("geo",    width=185, minwidth=140, anchor="w")
        self.hist_tree.column("isp",    width=160, minwidth=100, anchor="w")
        self.hist_tree.column("date",   width=90,  minwidth=80,  anchor="center")
        self.hist_tree.column("status", width=36,  minwidth=36,  anchor="center")

        self.hist_tree.tag_configure("ok",      foreground=self.GREEN)
        self.hist_tree.tag_configure("warn",     foreground=self.YELLOW)
        self.hist_tree.tag_configure("fail",     foreground=self.RED)
        self.hist_tree.tag_configure("unknown",  foreground=self.MUTED)

        self.hist_tree.bind("<Double-1>", lambda _e: self._hist_load())

        # ── Кнопки действий ──────────────────────────────────────────────────
        btn_frame = tk.Frame(p, bg=self.BG)
        btn_frame.pack(fill="x", padx=12, pady=(2, 4))

        btn_cfg = dict(bg=self.SURF, fg=self.TEXT, font=("Segoe UI", 9),
                       relief="flat", cursor="hand2",
                       activebackground="#45475a", activeforeground=self.TEXT,
                       width=14)

        self.btn_hist_load = tk.Button(btn_frame, **btn_cfg,
                                       command=self._hist_load)
        self.btn_hist_load.pack(side="left")

        self.btn_hist_check = tk.Button(btn_frame, **btn_cfg,
                                        command=self._hist_check)
        self.btn_hist_check.pack(side="left", padx=(8, 0))

        self.btn_hist_delete = tk.Button(btn_frame, **btn_cfg,
                                         command=self._hist_delete)
        self.btn_hist_delete.pack(side="left", padx=(8, 0))

        # ── Подсказка ─────────────────────────────────────────────────────────
        self.lbl_hist_hint = tk.Label(p, bg=self.BG, fg=self.MUTED,
                                      font=("Segoe UI", 8))
        self.lbl_hist_hint.pack(pady=(0, 8))

        self._refresh_hist_table()

    def _entry(self, parent, var, width=30):
        return tk.Entry(
            parent, textvariable=var, width=width,
            bg=self.SURF, fg=self.TEXT, insertbackground=self.TEXT,
            relief="flat", font=("Consolas", 10),
        )

    # ── Язык ──────────────────────────────────────────────────────────────────

    def _set_lang(self, lang: str):
        self.lang = lang
        self._apply_lang()

    def _apply_lang(self):
        t = S[self.lang]
        self.root.title(t["title"])
        self.lbl_title.config(text="JackalRouter")
        self.lbl_subtitle.config(text=t["subtitle"])
        self.lbl_ip.config(text=t["ip_label"])
        self.lbl_proxy.config(text=t["proxy_label"])
        self.lbl_hint.config(text=t["hint"])
        self.btn_apply.config(text=t["btn_apply"])
        self.btn_check.config(text=t["btn_check"])
        self.btn_udp.config(text=t["btn_udp"])
        self.btn_clean.config(text=t["btn_clean"])
        self.btn_server.config(text=t["btn_server"])
        self.lbl_log.config(text=t["log_header"])
        self.lbl_cur_title.config(text=t["cur_label"])
        if not getattr(self, "_cur_set", False):
            self.lbl_cur_val.config(text=t["cur_none"], fg=self.MUTED)

        active_bg, active_fg     = self.BLUE, self.BG
        inactive_bg, inactive_fg = self.SURF, self.MUTED
        if self.lang == "ru":
            self.btn_ru.config(bg=active_bg,   fg=active_fg)
            self.btn_en.config(bg=inactive_bg, fg=inactive_fg)
        else:
            self.btn_en.config(bg=active_bg,   fg=active_fg)
            self.btn_ru.config(bg=inactive_bg, fg=inactive_fg)

        if not self.status_var.get():
            self.status_var.set(t["ready"])

        self.notebook.tab(0, text=t["tab_main"])
        self.notebook.tab(1, text=t["tab_history"])

        self.btn_hist_load.config(text=t["hist_load"])
        self.btn_hist_check.config(text=t["hist_check"])
        self.btn_hist_delete.config(text=t["hist_delete"])
        self.lbl_hist_hint.config(text=t["hist_dblclick"])
        for col, key in [("server", "hist_col_proxy"), ("geo", "hist_col_geo"),
                         ("isp",    "hist_col_isp"),   ("date", "hist_col_date"),
                         ("status", "hist_col_st")]:
            self.hist_tree.heading(col, text=t[key])

    def _paste_proxy(self, event):
        try:
            text = self.root.clipboard_get()
            event.widget.delete(0, tk.END)
            event.widget.insert(0, text.strip())
        except Exception:
            pass
        return "break"

    def _(self, key: str, *args) -> str:
        s = S[self.lang][key]
        return s.format(*args) if args else s

    # ── Логирование ───────────────────────────────────────────────────────────

    def _log(self, msg: str, tag: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.config(state="normal")
        self.log.insert("end", f"[{ts}] {msg}\n", tag)
        self.log.see("end")
        self.log.config(state="disabled")

    def _status(self, msg: str, color: str = None):
        self.status_var.set(msg)
        self.status_lbl.config(fg=color or self.TEXT)

    def _set_buttons(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.btn_apply.config(state=state)
        self.btn_check.config(state=state)
        self.btn_udp.config(state=state)
        self.btn_clean.config(state=state)
        self.btn_server.config(state=state)
        self.btn_cur.config(state=state)
        self.btn_hist_load.config(state=state)
        self.btn_hist_check.config(state=state)
        self.btn_hist_delete.config(state=state)

    # ── Применить прокси ──────────────────────────────────────────────────────

    def _on_apply(self):
        proxy     = self.proxy_var.get().strip()
        ubuntu_ip = self.ip_var.get().strip()

        if not ubuntu_ip:
            self._log(self._("err_no_ip"), "err"); return
        if not proxy:
            self._log(self._("err_no_proxy"), "err"); return
        if not parse_proxy(proxy):
            self._log(self._("err_format", proxy), "err")
            self._log(self._("err_format2"), "warn"); return

        self._pending_proxy = proxy
        self._set_buttons(False)
        self._status(self._("sending"), self.YELLOW)
        self._log(self._("log_sending", ubuntu_ip, SERVER_PORT), "info")
        threading.Thread(target=self._send, args=(ubuntu_ip, proxy), daemon=True).start()

    def _send(self, ubuntu_ip: str, proxy: str):
        url = f"http://{ubuntu_ip}:{SERVER_PORT}/set_proxy"
        try:
            resp = requests.post(url, json={"proxy_string": proxy}, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            self.root.after(0, self._on_apply_ok, data)
        except requests.exceptions.ConnectionError:
            self.root.after(0, self._on_apply_err,
                self._("log_conn_err", ubuntu_ip, SERVER_PORT))
        except requests.exceptions.Timeout:
            self.root.after(0, self._on_apply_err,
                self._("log_timeout", TIMEOUT))
        except requests.exceptions.HTTPError as e:
            detail = ""
            try: detail = e.response.json().get("detail", "")
            except Exception: pass
            self.root.after(0, self._on_apply_err,
                self._("log_http_err", e.response.status_code, detail))
        except Exception as e:
            self.root.after(0, self._on_apply_err, self._("log_unk_err", e))

    def _on_apply_ok(self, data: dict):
        self._log(self._("log_ok", data.get("proxy", "")), "ok")
        self._status(self._("st_ok"), self.GREEN)
        self._set_buttons(True)
        self._hist_upsert(self._pending_proxy, status="unknown")
        # Сразу показать, какой IP теперь раздаётся
        self._on_refresh_current()

    def _on_apply_err(self, msg: str):
        self._log(msg, "err")
        self._status(self._("st_err"), self.RED)
        self._set_buttons(True)

    # ── Проверка прокси ───────────────────────────────────────────────────────

    def _on_check(self):
        proxy_str = self.proxy_var.get().strip()
        if not proxy_str:
            self._log(self._("err_no_proxy"), "err"); return

        p = parse_proxy(proxy_str)
        if not p:
            self._log(self._("err_format", proxy_str), "err")
            self._log(self._("err_format2"), "warn"); return

        self._set_buttons(False)
        self._status(self._("checking"), self.YELLOW)
        self._log(self._("chk_start", p["ip"], p["port"]), "info")
        threading.Thread(target=self._check_proxy, args=(p, proxy_str), daemon=True).start()

    def _check_proxy(self, p: dict, proxy_str: str = ""):
        ok, reason = socks5_ping(p["ip"], p["port"], p["user"], p["password"])
        if not ok:
            if proxy_str:
                ps = proxy_str
                self.root.after(0, lambda: self._hist_upsert(ps, status="fail"))
            self.root.after(0, self._on_check_fail, self._("chk_fail", reason))
            return

        u  = quote(p["user"],     safe="")
        pw = quote(p["password"], safe="")
        proxies = {
            "http":  f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
            "https": f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
        }

        data = None
        for url in GEO_URLS:
            try:
                resp = requests.get(url, proxies=proxies, timeout=TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                if data:
                    break
            except Exception:
                data = None

        if data is None or ("status" in data and data.get("status") != "success"):
            warn = ("⚠ Прокси работает (гео недоступно)"
                    if self.lang == "ru" else "⚠ Proxy works (geo unavailable)")
            if proxy_str:
                ps = proxy_str
                self.root.after(0, lambda: self._hist_upsert(ps, status="warn"))
            self.root.after(0, self._on_check_warn, warn)
            return

        ip      = data.get("query") or data.get("ip", "?")
        country = data.get("country", "?")
        code    = data.get("countryCode", "?")
        region  = data.get("regionName") or data.get("region", "?")
        city    = data.get("city", "?")
        isp     = data.get("isp") or data.get("org", "?")

        if code == "US":
            status = "ok"
            msg    = self._("chk_ok", ip, city, region, isp)
            cb     = self._on_check_ok
        elif ip not in ("?", None, ""):
            status = "warn"
            msg    = self._("chk_warn", ip, country, city)
            cb     = self._on_check_warn
        else:
            status = "warn"
            msg    = ("⚠ Прокси работает (гео недоступно)"
                      if self.lang == "ru" else "⚠ Proxy works (geo unavailable)")
            cb     = self._on_check_warn

        if proxy_str:
            ps, gd, st = proxy_str, data, status
            self.root.after(0, lambda: self._hist_upsert(ps, geo_data=gd, status=st))

        self.root.after(0, cb, msg)

    def _on_check_ok(self, msg: str):
        self._log(msg, "ok")
        self._status(self._("chk_st_ok"), self.GREEN)
        self._set_buttons(True)

    def _on_check_warn(self, msg: str):
        self._log(msg, "warn")
        self._status(self._("chk_st_warn"), self.YELLOW)
        self._set_buttons(True)

    def _on_check_fail(self, msg: str):
        self._log(msg, "err")
        self._status(self._("chk_st_fail"), self.RED)
        self._set_buttons(True)

    # ── Проверка UDP ASSOCIATE ─────────────────────────────────────────────────

    def _on_udp_check(self):
        proxy_str = self.proxy_var.get().strip()
        if not proxy_str:
            self._log(self._("err_no_proxy"), "err"); return

        p = parse_proxy(proxy_str)
        if not p:
            self._log(self._("err_format", proxy_str), "err")
            self._log(self._("err_format2"), "warn"); return

        self._set_buttons(False)
        self._status(self._("udp_checking"), self.YELLOW)
        self._log(self._("udp_start", p["ip"], p["port"]), "info")
        threading.Thread(target=self._udp_check, args=(p,), daemon=True).start()

    def _udp_check(self, p: dict):
        ok, reason = socks5_udp_check(p["ip"], p["port"], p["user"], p["password"])
        if ok:
            self.root.after(0, self._on_udp_ok, self._("udp_ok"))
        else:
            self.root.after(0, self._on_udp_fail, self._("udp_fail", reason))

    def _on_udp_ok(self, msg: str):
        self._log(msg, "ok")
        self._status(self._("udp_st_ok"), self.GREEN)
        self._set_buttons(True)

    def _on_udp_fail(self, msg: str):
        self._log(msg, "err")
        self._log(self._("udp_note"), "warn")
        self._status(self._("udp_st_fail"), self.RED)
        self._set_buttons(True)

    # ── Проверка чистоты (репутация + скорость) ────────────────────────────────

    def _on_clean_check(self):
        proxy_str = self.proxy_var.get().strip()
        if not proxy_str:
            self._log(self._("err_no_proxy"), "err"); return

        p = parse_proxy(proxy_str)
        if not p:
            self._log(self._("err_format", proxy_str), "err")
            self._log(self._("err_format2"), "warn"); return

        self._set_buttons(False)
        self._status(self._("clean_checking"), self.YELLOW)
        self._log(self._("clean_start", p["ip"], p["port"]), "info")
        threading.Thread(target=self._clean_check, args=(p, proxy_str), daemon=True).start()

    def _clean_check(self, p: dict, proxy_str: str = ""):
        # ── Шаг 1: прокси вообще живой? ──────────────────────────────────────
        ok, reason = socks5_ping(p["ip"], p["port"], p["user"], p["password"])
        if not ok:
            if proxy_str:
                ps = proxy_str
                self.root.after(0, lambda: self._hist_upsert(ps, status="fail"))
            self.root.after(0, self._on_clean_fail, self._("chk_fail", reason))
            return

        u  = quote(p["user"],     safe="")
        pw = quote(p["password"], safe="")
        proxies = {
            "http":  f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
            "https": f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
        }

        # ── Шаг 2: репутация через открытый источник (ip-api security-флаги) ──
        data = None
        try:
            resp = requests.get(CLEAN_URL, proxies=proxies, timeout=TIMEOUT)
            resp.raise_for_status()
            j = resp.json()
            if j.get("status") == "success":
                data = j
        except Exception:
            data = None

        # ── Шаг 3: замер скорости (всегда, даже если репутация недоступна) ───
        mbps, kbps, latency = measure_speed(proxies)

        self.root.after(0, self._on_clean_result, data, proxy_str,
                        mbps, kbps, latency)

    def _on_clean_result(self, data, proxy_str, mbps, kbps, latency):
        # ── Вердикт по флагам ────────────────────────────────────────────────
        if data is None:
            self._log(self._("clean_geo_na"), "warn")
            verdict_status = "warn"
            status_txt, status_col = self._("clean_st_warn"), self.YELLOW
        else:
            ip      = data.get("query", "?")
            country = data.get("country", "?")
            city    = data.get("city", "?")
            isp     = data.get("isp") or data.get("org", "?")
            is_proxy   = bool(data.get("proxy"))
            is_hosting = bool(data.get("hosting"))
            is_mobile  = bool(data.get("mobile"))
            rdns       = data.get("reverse", "")

            self._log(self._("clean_geo", ip, country, city, isp), "info")

            if is_proxy:
                self._log(self._("clean_dirty"), "err")
                verdict_status = "fail"
                status_txt, status_col = self._("clean_st_fail"), self.RED
            elif is_hosting:
                self._log(self._("clean_host"), "warn")
                verdict_status = "warn"
                status_txt, status_col = self._("clean_st_warn"), self.YELLOW
            else:
                self._log(self._("clean_ok"), "ok")
                verdict_status = "ok"
                status_txt, status_col = self._("clean_st_ok"), self.GREEN

            self._log(self._("clean_flags", is_proxy, is_hosting, is_mobile),
                      "err" if (is_proxy or is_hosting) else "ok")
            if rdns:
                self._log(self._("clean_rdns", rdns), "info")

        # ── Скорость ─────────────────────────────────────────────────────────
        speed_str = None
        if mbps is not None:
            speed_str = f"{mbps:.1f} Mbps ({kbps:.0f} KB/s)"
            lat = latency if latency is not None else "?"
            self._log(self._("clean_speed", speed_str, lat),
                      "ok" if mbps >= 2 else "warn")
        else:
            self._log(self._("clean_speed_na"), "err")

        self._status(status_txt, status_col)
        self._set_buttons(True)

        # ── Сохранить в историю (гео + статус + скорость) ────────────────────
        if proxy_str:
            extra = {}
            if speed_str:
                extra["speed"] = speed_str
            self._hist_upsert(proxy_str, geo_data=data,
                              status=verdict_status, extra=extra or None)

    def _on_clean_fail(self, msg: str):
        self._log(msg, "err")
        self._status(self._("chk_st_fail"), self.RED)
        self._set_buttons(True)

    # ── Проверка сервера ──────────────────────────────────────────────────────

    def _on_server_check(self):
        ubuntu_ip = self.ip_var.get().strip()
        if not ubuntu_ip:
            self._log(self._("err_no_ip"), "err")
            return
        self._set_buttons(False)
        self._status(self._("srv_checking"), self.YELLOW)
        self._log(f"→  GET http://{ubuntu_ip}:{SERVER_PORT}/status", "info")
        threading.Thread(target=self._server_check, args=(ubuntu_ip,), daemon=True).start()

    def _server_check(self, ubuntu_ip: str):
        url = f"http://{ubuntu_ip}:{SERVER_PORT}/status"
        try:
            resp = requests.get(url, timeout=TIMEOUT)
            resp.raise_for_status()
            self.root.after(0, self._on_server_result, resp.json())
        except requests.exceptions.ConnectionError:
            self.root.after(0, self._on_server_down, ubuntu_ip, "connection refused")
        except requests.exceptions.Timeout:
            self.root.after(0, self._on_server_down, ubuntu_ip, f"timeout {TIMEOUT}s")
        except Exception as e:
            self.root.after(0, self._on_server_down, ubuntu_ip, str(e))

    def _on_server_result(self, data: dict):
        svcs = [
            ("sing_box", self._("srv_desc_sb")),
            ("dnsmasq",  self._("srv_desc_dns")),
        ]
        all_ok = (
            all(data.get(s) == "active" for s, _ in svcs) and
            data.get("iptables") == "ok"
        )
        header_key = "srv_up" if all_ok else "srv_warn"
        header_tag = "ok"     if all_ok else "warn"
        self._log(self._(header_key), header_tag)
        for svc, label in svcs:
            state = data.get(svc, "unknown")
            ok    = state == "active"
            self._log(f"   {'●' if ok else '○'}  {svc:<12} {state:<10}  {label}",
                      "ok" if ok else "warn")
        ipt_ok  = data.get("iptables") == "ok"
        ipt_lbl = self._("srv_ipt_ok") if ipt_ok else self._("srv_ipt_err")
        self._log(f"   {'●' if ipt_ok else '○'}  {'iptables':<12} {ipt_lbl}",
                  "ok" if ipt_ok else "err")
        proxy = data.get("proxy")
        self._log(
            self._("srv_proxy", proxy) if proxy else self._("srv_no_proxy"),
            "info" if proxy else "warn",
        )
        self._status(
            self._("srv_st_ok") if all_ok else self._("srv_st_warn"),
            self.GREEN if all_ok else self.YELLOW,
        )
        self._set_buttons(True)
        # Обновить баннер «сейчас раздаётся»
        if proxy:
            self._on_refresh_current()

    def _on_server_down(self, ubuntu_ip: str, reason: str):
        self._log(self._("srv_down", ubuntu_ip, SERVER_PORT), "err")
        self._log(f"   {reason}", "err")
        self._log(self._("srv_hint"), "warn")
        self._status(self._("srv_st_down"), self.RED)
        self._set_buttons(True)

    # ── Сейчас раздаётся: exit-IP активного прокси + гео ───────────────────────

    def _set_current(self, text: str, color: str = None, mark: bool = True):
        self._cur_set = mark
        self.lbl_cur_val.config(text=text, fg=color or self.MUTED)
        self.btn_cur.config(state="normal")

    def _on_refresh_current(self):
        ubuntu_ip = self.ip_var.get().strip()
        if not ubuntu_ip:
            self._set_current(self._("cur_err", self._("err_no_ip")), self.RED)
            return
        self.btn_cur.config(state="disabled")
        self._set_current(self._("cur_loading"), self.YELLOW)
        threading.Thread(target=self._refresh_current_worker,
                         args=(ubuntu_ip,), daemon=True).start()

    def _refresh_current_worker(self, ubuntu_ip: str):
        # 1) Авторитетный путь: сервер сам ходит через активный прокси
        try:
            r = requests.get(f"http://{ubuntu_ip}:{SERVER_PORT}/current_ip",
                             timeout=25)
            if r.status_code == 200:
                d = r.json()
                if d.get("ok"):
                    self.root.after(0, self._show_current,
                                    d.get("exit_ip"), d.get("countryCode"),
                                    d.get("country"), d.get("city"), d.get("isp"))
                    return
                # Сервер ответил, но прокси не задан / гео не получено
                err = d.get("error", "?")
                if "не задан" in err or "no proxy" in err or "tag=proxy" in err:
                    self.root.after(0, self._set_current,
                                    self._("cur_no_proxy"), self.YELLOW)
                    return
                # иначе пробуем клиентский fallback (вдруг временный сбой гео)
        except Exception:
            pass
        # 2) Fallback: старый сервер без /current_ip → берём ip:port из /status,
        #    учётку ищем в текущем поле или в истории, гео меряем сами.
        self._fallback_current(ubuntu_ip)

    def _fallback_current(self, ubuntu_ip: str):
        try:
            r = requests.get(f"http://{ubuntu_ip}:{SERVER_PORT}/status",
                             timeout=TIMEOUT)
            r.raise_for_status()
            active = r.json().get("proxy")
        except Exception as e:
            self.root.after(0, self._set_current, self._("cur_err", str(e)), self.RED)
            return
        if not active:
            self.root.after(0, self._set_current, self._("cur_no_proxy"), self.YELLOW)
            return

        full = self._creds_for(active)
        p = parse_proxy(full) if full else None
        if not p:
            self.root.after(0, self._set_current,
                            self._("cur_partial", active), self.YELLOW)
            return

        u  = quote(p["user"],     safe="")
        pw = quote(p["password"], safe="")
        proxies = {
            "http":  f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
            "https": f"socks5h://{u}:{pw}@{p['ip']}:{p['port']}",
        }
        data = None
        for url in GEO_URLS:
            try:
                resp = requests.get(url, proxies=proxies, timeout=TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                if data:
                    break
            except Exception:
                data = None
        if not data or ("status" in data and data.get("status") != "success"):
            self.root.after(0, self._set_current,
                            self._("cur_partial", active), self.YELLOW)
            return
        self.root.after(0, self._show_current,
                        data.get("query") or data.get("ip"),
                        data.get("countryCode"), data.get("country"),
                        data.get("city"), data.get("isp") or data.get("org"))

    def _show_current(self, ip, code, country, city, isp):
        flag = self._flag(code or "")
        geo  = f"{flag} {code or '?'}, {city or country or '?'}".strip()
        self._set_current(self._("cur_fmt", ip or "?", geo, isp or "?"), self.GREEN)

    def _creds_for(self, display: str):
        """Ищет полную строку прокси (с учёткой) для активного ip:port —
        сначала в текущем поле, затем в истории."""
        cur = self.proxy_var.get().strip()
        p = parse_proxy(cur)
        if p and f"{p['ip']}:{p['port']}" == display:
            return cur
        for e in self.history:
            if e.get("display") == display:
                return e.get("proxy")
        return None

    # ── История ───────────────────────────────────────────────────────────────

    def _load_history(self) -> list:
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def _save_history(self):
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    @staticmethod
    def _flag(code: str) -> str:
        if not code or len(code) != 2:
            return ""
        try:
            return (chr(0x1F1E6 + ord(code[0].upper()) - 65) +
                    chr(0x1F1E6 + ord(code[1].upper()) - 65))
        except Exception:
            return ""

    def _hist_upsert(self, proxy_str: str, geo_data: dict = None,
                     status: str = "unknown", extra: dict = None):
        """Add or update a history entry keyed by IP:port."""
        if not proxy_str:
            return
        p = parse_proxy(proxy_str)
        if not p:
            return
        display = f"{p['ip']}:{p['port']}"
        now = datetime.now().strftime("%d.%m %H:%M")

        for entry in self.history:
            if entry.get("display") == display:
                entry["proxy"]     = proxy_str
                entry["last_used"] = now
                if status != "unknown":
                    entry["status"] = status
                if geo_data:
                    entry["country"]      = geo_data.get("country", "?")
                    entry["country_code"] = geo_data.get("countryCode", "?")
                    entry["city"]         = geo_data.get("city", "?")
                    entry["isp"]          = (geo_data.get("isp") or
                                             geo_data.get("org", "?"))
                if extra:
                    entry.update(extra)
                self._save_history()
                self.root.after(0, self._refresh_hist_table)
                return

        entry = {
            "proxy":        proxy_str,
            "display":      display,
            "country":      geo_data.get("country", "?")      if geo_data else "?",
            "country_code": geo_data.get("countryCode", "?")  if geo_data else "?",
            "city":         geo_data.get("city", "?")         if geo_data else "?",
            "isp":          (geo_data.get("isp") or geo_data.get("org", "?")) if geo_data else "?",
            "last_used":    now,
            "status":       status,
        }
        if extra:
            entry.update(extra)
        self.history.insert(0, entry)
        if len(self.history) > 50:
            self.history = self.history[:50]
        self._save_history()
        self.root.after(0, self._refresh_hist_table)

    def _refresh_hist_table(self):
        for row in self.hist_tree.get_children():
            self.hist_tree.delete(row)
        for i, e in enumerate(self.history):
            code     = e.get("country_code", "")
            flag     = self._flag(code)
            city     = e.get("city", "?")
            geo_str  = f"{flag} {code} / {city}" if code and code != "?" else "?"
            isp      = e.get("isp", "?")
            isp_disp = (isp[:22] + "…") if len(isp) > 23 else isp
            date     = e.get("last_used", "?")
            st       = e.get("status", "unknown")
            icon     = {"ok": "✓", "warn": "⚠", "fail": "✗"}.get(st, "?")
            tag      = st if st in ("ok", "warn", "fail") else "unknown"
            self.hist_tree.insert("", "end", iid=str(i),
                values=(e.get("display", "?"), geo_str, isp_disp, date, icon),
                tags=(tag,))

    def _hist_selected_idx(self):
        sel = self.hist_tree.selection()
        if not sel:
            self._log(self._("hist_nosel"), "warn")
            return None
        return int(sel[0])

    def _hist_load(self):
        idx = self._hist_selected_idx()
        if idx is None:
            return
        entry = self.history[idx]
        self.proxy_var.set(entry["proxy"])
        self.notebook.select(0)
        self._log(self._("hist_loaded", entry["display"]), "info")

    def _hist_check(self):
        idx = self._hist_selected_idx()
        if idx is None:
            return
        entry = self.history[idx]
        p = parse_proxy(entry["proxy"])
        if not p:
            return
        self._set_buttons(False)
        self._status(self._("hist_checking"), self.YELLOW)
        self._log(self._("chk_start", p["ip"], p["port"]), "info")
        threading.Thread(
            target=self._check_proxy,
            args=(p, entry["proxy"]),
            daemon=True,
        ).start()

    def _hist_delete(self):
        idx = self._hist_selected_idx()
        if idx is None:
            return
        del self.history[idx]
        self._save_history()
        self._refresh_hist_table()


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
