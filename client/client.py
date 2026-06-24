#!/usr/bin/env python3
"""
JackalRouter — Control Panel (Windows, Tkinter)
Features: proxy apply, proxy check + geo, EN/RU language toggle.
"""

import tkinter as tk
from tkinter import scrolledtext
import threading
import re
import socket
from datetime import datetime
from urllib.parse import quote

try:
    import requests
    requests.get  # ensure it's usable
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests[socks]"])
    import requests

try:
    import socks  # PySocks — needed for SOCKS5 support in requests
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "PySocks"])

SERVER_PORT = 8000
TIMEOUT     = 15
CHECK_URL   = "http://ip-api.com/json?fields=status,country,countryCode,regionName,city,isp,query"

GEO_URLS = [
    "http://ip-api.com/json?fields=status,country,countryCode,regionName,city,isp,query",
    "http://ip-api.com/json",
    "http://ipinfo.io/json",
]


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
        # CONNECT запрос (ATYP=0x03 hostname)
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

# ── Строки интерфейса ─────────────────────────────────────────────────────────

S = {
    "ru": {
        "title":          "JackalRouter — Пульт управления",
        "subtitle":       "Управление прокси-маршрутизацией",
        "ip_label":       "IP Ubuntu:",
        "proxy_label":    "Прокси:",
        "hint":           "Формат: ip:port:user:pass  или  user:pass@ip:port",
        "btn_apply":      "  Route  ",
        "btn_check":      "⬡  Проверить прокси",
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
    },
    "en": {
        "title":          "JackalRouter — Control Panel",
        "subtitle":       "Proxy routing management",
        "ip_label":       "Ubuntu IP:",
        "proxy_label":    "Proxy:",
        "hint":           "Format: ip:port:user:pass  or  user:pass@ip:port",
        "btn_apply":      "  Route  ",
        "btn_check":      "⬡  Check proxy",
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
    },
}

# ── Парсинг прокси ────────────────────────────────────────────────────────────

def parse_proxy(s: str):
    """Returns dict(ip, port, user, password) or None."""
    s = s.strip()
    # Убираем схему: socks5h://, socks5://, http:// и т.п.
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
        root.geometry("740x530")
        root.resizable(False, False)
        root.configure(bg=self.BG)
        self._build()
        self._apply_lang()

    # ── Построение UI ─────────────────────────────────────────────────────────

    def _build(self):
        # ── Топ-бар: заголовок + переключатель языка ─────────────────────────
        top = tk.Frame(self.root, bg=self.BG)
        top.pack(fill="x", padx=16, pady=(14, 0))

        left = tk.Frame(top, bg=self.BG)
        left.pack(side="left", fill="x", expand=True)

        self.lbl_title = tk.Label(left, bg=self.BG, fg=self.BLUE,
                                  font=("Segoe UI", 16, "bold"))
        self.lbl_title.pack(anchor="w")
        self.lbl_subtitle = tk.Label(left, bg=self.BG, fg=self.MUTED,
                                     font=("Segoe UI", 9))
        self.lbl_subtitle.pack(anchor="w")

        # Переключатель RU / EN
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

        # ── IP Ubuntu ────────────────────────────────────────────────────────
        row1 = tk.Frame(self.root, bg=self.BG)
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
        row2 = tk.Frame(self.root, bg=self.BG)
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

        # ── Кнопка проверки + хинт ───────────────────────────────────────────
        row3 = tk.Frame(self.root, bg=self.BG)
        row3.pack(fill="x", padx=16, pady=(2, 6))

        # Кнопка "Проверить прокси"
        self.btn_check = tk.Button(
            row3, text="", width=20,
            bg=self.SURF, fg=self.TEXT,
            font=("Segoe UI", 9), relief="flat", cursor="hand2",
            activebackground="#45475a", activeforeground=self.TEXT,
            command=self._on_check,
        )
        self.btn_check.pack(side="left")

        self.lbl_hint = tk.Label(row3, bg=self.BG, fg=self.MUTED,
                                 font=("Segoe UI", 8))
        self.lbl_hint.pack(side="left", padx=(12, 0))

        # ── Кнопка «Применить» ───────────────────────────────────────────────
        self.btn_apply = tk.Button(
            self.root, text="",
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
            self.root, textvariable=self.status_var,
            bg=self.BG, fg=self.TEXT, font=("Segoe UI", 10, "bold")
        )
        self.status_lbl.pack()

        # ── Лог ──────────────────────────────────────────────────────────────
        log_frame = tk.Frame(self.root, bg=self.BG)
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
        self.btn_server.config(text=t["btn_server"])
        self.lbl_log.config(text=t["log_header"])

        # подсветить активный язык
        active_bg   = self.BLUE
        active_fg   = self.BG
        inactive_bg = self.SURF
        inactive_fg = self.MUTED
        if self.lang == "ru":
            self.btn_ru.config(bg=active_bg,   fg=active_fg)
            self.btn_en.config(bg=inactive_bg, fg=inactive_fg)
        else:
            self.btn_en.config(bg=active_bg,   fg=active_fg)
            self.btn_ru.config(bg=inactive_bg, fg=inactive_fg)

        if not self.status_var.get():
            self.status_var.set(t["ready"])

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
        self.btn_server.config(state=state)

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
        threading.Thread(target=self._check_proxy, args=(p,), daemon=True).start()

    def _check_proxy(self, p: dict):
        # ── Шаг 1: raw SOCKS5 хендшейк (быстро, точно, не зависит от HTTP) ──
        ok, reason = socks5_ping(p["ip"], p["port"], p["user"], p["password"])
        if not ok:
            self.root.after(0, self._on_check_fail, self._("chk_fail", reason))
            return

        # ── Шаг 2: HTTP-запрос через прокси для гео-инфо (best-effort) ───────
        u = quote(p["user"],     safe="")
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

        if data is None:
            # SOCKS5 работает, но гео-сервисы недоступны — всё равно ОК
            warn = ("⚠ Прокси работает (гео недоступно)"
                    if self.lang == "ru" else "⚠ Proxy works (geo unavailable)")
            self.root.after(0, self._on_check_warn, warn)
            return

        if "status" in data and data.get("status") != "success":
            warn = ("⚠ Прокси работает (гео недоступно)"
                    if self.lang == "ru" else "⚠ Proxy works (geo unavailable)")
            self.root.after(0, self._on_check_warn, warn)
            return

        ip      = data.get("query") or data.get("ip", "?")
        country = data.get("country", "?")
        code    = data.get("countryCode", "?")
        region  = data.get("regionName") or data.get("region", "?")
        city    = data.get("city", "?")
        isp     = data.get("isp") or data.get("org", "?")

        if code == "US":
            self.root.after(0, self._on_check_ok,
                self._("chk_ok", ip, city, region, isp))
        elif ip not in ("?", None, ""):
            self.root.after(0, self._on_check_warn,
                self._("chk_warn", ip, country, city))
        else:
            warn = ("⚠ Прокси работает (гео недоступно)"
                    if self.lang == "ru" else "⚠ Proxy works (geo unavailable)")
            self.root.after(0, self._on_check_warn, warn)

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
            ok = state == "active"
            dot = "●" if ok else "○"
            self._log(f"   {dot}  {svc:<12} {state:<10}  {label}",
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

    def _on_server_down(self, ubuntu_ip: str, reason: str):
        self._log(self._("srv_down", ubuntu_ip, SERVER_PORT), "err")
        self._log(f"   {reason}", "err")
        self._log(self._("srv_hint"), "warn")
        self._status(self._("srv_st_down"), self.RED)
        self._set_buttons(True)


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
