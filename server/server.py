#!/usr/bin/env python3
"""
JackalRouter — FastAPI-сервер для Ubuntu
Управляет sing-box (TProxy) и правилами iptables.
Запускать от root: sudo python3 server.py
"""

import subprocess
import json
import re
import os
import logging
from typing import Tuple
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# ── Настройки ─────────────────────────────────────────────────────────────────
INT_IFACE    = "enp3s0"                   # LAN-интерфейс (к техническому роутеру)
SINGBOX_PORT = 7893                        # TProxy inbound port
SINGBOX_CONF = "/etc/sing-box/config.json"
SERVER_PORT  = 8000
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="JackalRouter Server")


class ProxyRequest(BaseModel):
    proxy_string: str


def run(cmd: str, check: bool = False) -> Tuple[int, str, str]:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"CMD failed: {cmd}\n{r.stderr.strip()}")
    return r.returncode, r.stdout.strip(), r.stderr.strip()


# ── sing-box конфиг ───────────────────────────────────────────────────────────

def make_singbox_conf(ip: str, port: int, user: str, password: str) -> dict:
    return {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15"},
                {"type": "tcp", "tag": "proxy-dns", "server": "8.8.8.8", "detour": "proxy"},
            ],
            "rules": [
                {"query_type": ["A"], "server": "fakeip"},
                {"query_type": [64, 65], "action": "reject"},
            ],
            "final": "proxy-dns",
            "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tproxy",
            "tag": "tproxy-in",
            "listen": "0.0.0.0",
            "listen_port": SINGBOX_PORT,
        }],
        "outbounds": [
            {
                "type": "socks",
                "tag": "proxy",
                "server": ip,
                "server_port": port,
                "version": "5",
                "username": user,
                "password": password,
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block",  "tag": "block"},
        ],
        "route": {
            "default_domain_resolver": "proxy-dns",
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
                # Блокируем DoH (DNS-over-HTTPS) и DoT (DNS-over-TLS):
                # телефон получит отказ → упадёт на plain UDP DNS :53 →
                # sing-box перехватит hijack-dns → ответит FakeIP (нет утечки IP)
                {"domain": ["dns.google", "one.one.one.one", "cloudflare-dns.com", "doh.pub", "doh.360.cn"], "outbound": "block"},
                {"port": 853, "outbound": "block"},
            ],
            "final": "proxy",
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
                "store_fakeip": True,
                "path": "/var/lib/sing-box/cache.db",
            }
        },
    }


def write_singbox_conf(ip: str, port: int, user: str, password: str):
    os.makedirs(os.path.dirname(SINGBOX_CONF), exist_ok=True)
    conf = make_singbox_conf(ip, port, user, password)
    with open(SINGBOX_CONF, "w") as f:
        json.dump(conf, f, indent=2)
    log.info(f"Записан {SINGBOX_CONF}  [{ip}:{port}]")


# ── iptables (TProxy) ─────────────────────────────────────────────────────────

def apply_iptables():
    log.info(f"Настраиваю iptables TProxy на интерфейсе {INT_IFACE}…")

    steps = [
        # Форвардинг
        "sysctl -w net.ipv4.ip_forward=1",

        # Policy routing: пакеты с меткой 1 → lo (локальная доставка для TProxy)
        "ip rule del fwmark 1 table 100 2>/dev/null || true",
        "ip rule add fwmark 1 table 100",
        "ip route del local default dev lo table 100 2>/dev/null || true",
        "ip route add local default dev lo table 100",

        # Убираем старую цепочку redsocks (nat), если осталась с прошлой версии
        f"iptables -t nat -D PREROUTING -i {INT_IFACE} -p tcp -j REDSOCKS 2>/dev/null || true",
        "iptables -t nat -F REDSOCKS 2>/dev/null || true",
        "iptables -t nat -X REDSOCKS 2>/dev/null || true",

        # MSS clamp 1280 — фиксим PMTUD через туннель (обе стороны enp3s0)
        f"iptables -t mangle -D PREROUTING -i {INT_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280 2>/dev/null || true",
        f"iptables -t mangle -A PREROUTING -i {INT_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280",
        f"iptables -t mangle -D POSTROUTING -o {INT_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280 2>/dev/null || true",
        f"iptables -t mangle -A POSTROUTING -o {INT_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280",

        # Mangle цепочка SING_BOX
        "iptables -t mangle -N SING_BOX 2>/dev/null || true",
        "iptables -t mangle -F SING_BOX",
        "iptables -t mangle -A SING_BOX -d 0.0.0.0/8 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 10.0.0.0/8 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 127.0.0.0/8 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 169.254.0.0/16 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 172.16.0.0/12 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 192.168.0.0/16 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 224.0.0.0/4 -j RETURN",
        "iptables -t mangle -A SING_BOX -d 240.0.0.0/4 -j RETURN",
        # Весь UDP (DNS :53 → FakeIP, QUIC :443, STUN…) → TProxy → sing-box →
        # SOCKS5 UDP ASSOCIATE. QUIC проксируется, а не блокируется: отсутствие
        # рабочего UDP/QUIC у "резидентного" IP повышает fraud-score антидетектов.
        f"iptables -t mangle -A SING_BOX -p udp -j TPROXY --on-port {SINGBOX_PORT} --tproxy-mark 1",
        # Весь TCP → TProxy → sing-box → SOCKS5 (domain отправляет по FakeIP-маппингу)
        f"iptables -t mangle -A SING_BOX -p tcp -j TPROXY --on-port {SINGBOX_PORT} --tproxy-mark 1",
        # Привязка к LAN-интерфейсу
        f"iptables -t mangle -D PREROUTING -i {INT_IFACE} -j SING_BOX 2>/dev/null || true",
        f"iptables -t mangle -A PREROUTING -i {INT_IFACE} -j SING_BOX",

        # MASQUERADE
        "iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null || "
        "iptables -t nat -A POSTROUTING -j MASQUERADE",

        # IPv6 полностью блокируем
        f"ip6tables -D FORWARD -i {INT_IFACE} -j DROP 2>/dev/null || true",
        f"ip6tables -A FORWARD -i {INT_IFACE} -j DROP",
        f"ip6tables -D FORWARD -o {INT_IFACE} -j DROP 2>/dev/null || true",
        f"ip6tables -A FORWARD -o {INT_IFACE} -j DROP",

        # Каталог для fakeip cache
        "mkdir -p /var/lib/sing-box",

        # Отключаем GRO/GSO/TSO: предотвращаем сборку сегментов больше MSS на enp3s0
        f"ethtool -K {INT_IFACE} gro off gso off tso off lro off 2>/dev/null || true",
    ]

    for cmd in steps:
        code, out, err = run(cmd)
        if code != 0 and err:
            log.warning(f"  [{code}] {cmd}  =>  {err}")

    log.info("iptables TProxy правила применены.")


# ── Утилиты ───────────────────────────────────────────────────────────────────

def parse_proxy(proxy_string: str) -> dict:
    s = proxy_string.strip()
    # Убираем схему: socks5h://, socks5://, http:// и т.п.
    s = re.sub(r'^[a-zA-Z0-9+.\-]+://', '', s)
    m = re.match(r'^([^:@]+):(.+)@([\d.]+):(\d+)$', s)
    if m:
        return {"ip": m.group(3), "port": int(m.group(4)),
                "user": m.group(1), "password": m.group(2)}
    parts = s.split(":", 3)
    if len(parts) == 4 and re.match(r'^\d{1,5}$', parts[1]):
        return {"ip": parts[0], "port": int(parts[1]),
                "user": parts[2], "password": parts[3]}
    raise ValueError(
        f"Неверный формат прокси: '{s}'. "
        "Ожидается 'ip:port:user:pass' или 'user:pass@ip:port'."
    )


# ── Lifecycle ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def on_startup():
    if os.geteuid() != 0:
        log.warning("Сервер запущен НЕ от root — правила iptables могут не примениться!")
    apply_iptables()


# ── Эндпоинты ─────────────────────────────────────────────────────────────────

@app.post("/set_proxy")
async def set_proxy(req: ProxyRequest):
    try:
        proxy = parse_proxy(req.proxy_string)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        write_singbox_conf(
            ip=proxy["ip"], port=proxy["port"],
            user=proxy["user"], password=proxy["password"],
        )
        code, _, err = run("systemctl restart sing-box")
        if code != 0:
            raise RuntimeError(f"systemctl restart sing-box: {err}")
        log.info("sing-box перезапущен успешно.")
        return {
            "status": "ok",
            "message": "Прокси применён, sing-box перезапущен.",
            "proxy": f"{proxy['ip']}:{proxy['port']}",
        }
    except Exception as e:
        log.error(f"Ошибка применения прокси: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/status")
async def status():
    def svc(name: str) -> str:
        _, out, _ = run(f"systemctl is-active {name}")
        return out.strip()

    iptables_ok = run("iptables -t mangle -L SING_BOX -n")[0] == 0

    proxy = None
    try:
        conf = json.load(open(SINGBOX_CONF))
        for ob in conf.get("outbounds", []):
            if ob.get("tag") == "proxy":
                proxy = f"{ob['server']}:{ob['server_port']}"
                break
    except Exception:
        pass

    return {
        "sing_box": svc("sing-box"),
        "dnsmasq":  svc("dnsmasq"),
        "iptables": "ok" if iptables_ok else "error",
        "iface":    INT_IFACE,
        "port":     SINGBOX_PORT,
        "proxy":    proxy,
    }


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=SERVER_PORT)
