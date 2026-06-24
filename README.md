# JackalRouter

**Zero-leak transparent SOCKS5 proxy gateway via Ubuntu + Technical Router**

[English](#english) · [Русский](#русский)

---

## English

### What is this?

JackalRouter turns an Ubuntu laptop into a **transparent proxy gateway** for any device connected to a secondary Wi-Fi router. Once deployed, every device on the router's network — phone, tablet, PC — routes all traffic through a US SOCKS5 proxy with **no configuration required on the device itself**.

All known leak vectors are plugged:

| Traffic type | Without JackalRouter | With JackalRouter |
|---|---|---|
| TCP (HTTP, HTTPS…) | Real IP | Proxy IP |
| UDP DNS `:53` | Real IP + ISP DNS | Direct → 8.8.8.8 (bypasses proxy) |
| WebRTC STUN `:3478` | Real IP (browser leak) | Proxy IP |
| WebRTC STUN `:19302` | Real IP (Chrome leak) | Proxy IP |
| UDP QUIC/HTTP3 `:443` | Real IP | **Blocked** (browser falls back to TCP) |
| Any other UDP | Real IP | **Blocked** |
| IPv6 | Real IPv6 address | **Blocked** |

### Architecture

```
Internet
   │
   ▼
Ubuntu Laptop  ◄──────── SSH ──────────  Windows PC
│  wlp2s0 (WAN, WiFi/LAN to internet)   (JackalRouter GUI client)
│
│  enp3s0 (LAN, 10.0.0.1/24)
│    │
│    ▼
Technical Router  (WAN = DHCP from 10.0.0.1)
│
├── Wi-Fi Device 1  (phone, tablet…)
├── Wi-Fi Device 2
└── …
```

**Traffic flow:**
1. Device sends TCP → Ubuntu intercepts via `iptables PREROUTING` → `redsocks` → SOCKS5 proxy
2. Device sends DNS (UDP :53) → forwarded directly to `8.8.8.8` (not proxied — DHCP tells devices to use 8.8.8.8)
3. Device sends WebRTC STUN (UDP :3478 / :19302) → DNAT to `redudp` → SOCKS5 proxy → Google STUN server → browser sees proxy IP
4. All other UDP → `iptables FORWARD DROP`
5. Any IPv6 → `ip6tables FORWARD DROP`

### Components

| File | Description |
|---|---|
| `server/server.py` | FastAPI server running on Ubuntu as root. Manages `redsocks` config and `iptables` rules. |
| `server/requirements.txt` | Python deps: fastapi, uvicorn, pydantic |
| `server/jackalrouter.service` | systemd unit file for auto-start |
| `server/redsocks.conf` | Placeholder redsocks config (overwritten at deploy time) |
| `client/client.py` | Windows Tkinter GUI — sends SOCKS5 proxy strings to the server |
| `client/requirements.txt` | Python deps: requests[socks], PySocks |
| `deploy.sh` | Full automated deployment script for Ubuntu |

### Requirements

**Ubuntu side:**
- Ubuntu 20.04+ (tested on 20.04 LTS)
- Two network interfaces: WAN (internet) + LAN (to secondary router)
- `sudo` access (deployment runs as root)

**Windows side:**
- Python 3.8+ with `pip`
- Packages: `pip install -r client/requirements.txt`
- Network access to Ubuntu's local IP

**Router:**
- Any Wi-Fi router with a WAN port
- WAN connection type set to **DHCP** (automatic IP)
- Connected to Ubuntu's LAN port via Ethernet cable

### Deployment

```bash
# On Ubuntu — run once:
sudo bash deploy.sh
```

The script will:
1. Check internet and system requirements
2. Auto-detect WAN and LAN interfaces
3. Resolve Google STUN server IP for WebRTC
4. Install packages: `redsocks`, `dnsmasq`, `iptables-persistent`, `dnsutils`
5. Assign static IP `10.0.0.1/24` to LAN interface (NetworkManager)
6. Configure `dnsmasq` as DHCP server (range `10.0.0.100–200`)
7. Apply all `iptables` + `ip6tables` rules (persistent across reboots)
8. Write `/etc/redsocks.conf` with three sections (TCP redsocks + 2×STUN redudp)
9. Install Python venv, install deps, register and start `jackalrouter` systemd service

At the end, the script prints step-by-step instructions for configuring the router's WAN to DHCP.

### Router configuration (one-time)

1. Connect cable: `Ubuntu LAN port → Router WAN port`
2. Connect phone/PC to the router's Wi-Fi
3. Open router admin panel (usually `192.168.0.1` or `192.168.1.1`)
4. Go to **WAN / Internet / Connection type** → set to **DHCP (Dynamic IP)**
5. Save and wait 15 seconds

### Client usage (Windows)

```bash
pip install -r client/requirements.txt
python client.py
```

1. Enter Ubuntu's local IP address
2. Paste a SOCKS5 proxy string in one of these formats:
   - `ip:port:username:password`
   - `username:password@ip:port`
3. Click **Check** to verify the proxy (shows IP, city, ISP, marks green if US)
4. Click **Route** to apply — all traffic on the router's network is now proxied

### API

The server exposes a simple REST API on port `8000`:

```
POST /set_proxy   {"proxy_string": "ip:port:user:pass"}
GET  /status      → {"redsocks": "active", "iface": "enp3s0", "port": 12345}
```

### How WebRTC spoofing works

Browsers (Chrome, Firefox) use the STUN protocol (UDP) to discover the real IP behind NAT — this is the "WebRTC leak." JackalRouter intercepts STUN packets in `iptables PREROUTING` (before routing), DNATs them to local `redudp` listeners, which forward them to Google STUN servers **through the SOCKS5 proxy**. The STUN server sees the proxy IP and returns it to the browser — so WebRTC also reports the proxy IP.

---

## Русский

### Что это?

JackalRouter превращает Ubuntu-ноутбук в **прозрачный прокси-шлюз** для всех устройств, подключённых к второму (техническому) Wi-Fi роутеру. После деплоя телефон, планшет, ноутбук — всё что подключится к этому роутеру — автоматически направляет трафик через SOCKS5 прокси **без каких-либо настроек на самом устройстве**.

Все известные каналы утечки IP закрыты:

| Тип трафика | Без JackalRouter | С JackalRouter |
|---|---|---|
| TCP (HTTP, HTTPS…) | Реальный IP | IP прокси |
| UDP DNS `:53` | Реальный IP + DNS провайдера | Напрямую → 8.8.8.8 (минуя прокси) |
| WebRTC STUN `:3478` | Реальный IP (утечка в браузере) | IP прокси |
| WebRTC STUN `:19302` | Реальный IP (утечка Chrome) | IP прокси |
| UDP QUIC/HTTP3 `:443` | Реальный IP | **Заблокирован** (браузер переключается на TCP) |
| Любой другой UDP | Реальный IP | **Заблокирован** |
| IPv6 | Реальный IPv6-адрес | **Заблокирован** |

### Архитектура

```
Интернет
   │
   ▼
Ubuntu-ноутбук  ◄──────── SSH ──────────  ПК на Windows
│  wlp2s0 (WAN — Wi-Fi/LAN в интернет)   (GUI-клиент JackalRouter)
│
│  enp3s0 (LAN, 10.0.0.1/24)
│    │
│    ▼
Технический роутер  (WAN = DHCP от 10.0.0.1)
│
├── Wi-Fi устройство 1  (телефон, планшет…)
├── Wi-Fi устройство 2
└── …
```

**Путь трафика:**
1. Устройство отправляет TCP → Ubuntu перехватывает через `iptables PREROUTING` → `redsocks` → SOCKS5 прокси
2. DNS (UDP :53) → напрямую на `8.8.8.8` (не через прокси — DHCP выдаёт устройствам 8.8.8.8)
3. WebRTC STUN (UDP :3478 / :19302) → DNAT на `redudp` → SOCKS5 прокси → STUN-сервер Google → браузер видит IP прокси
4. Любой другой UDP → `iptables FORWARD DROP`
5. IPv6 → `ip6tables FORWARD DROP`

### Состав проекта

| Файл | Описание |
|---|---|
| `server/server.py` | FastAPI-сервер на Ubuntu (запускается от root). Управляет конфигом `redsocks` и правилами `iptables`. |
| `server/requirements.txt` | Python-зависимости: fastapi, uvicorn, pydantic |
| `server/jackalrouter.service` | Юнит systemd для автозапуска |
| `server/redsocks.conf` | Плейсхолдер конфига redsocks (перезаписывается при деплое) |
| `client/client.py` | GUI-клиент на Windows (Tkinter) — отправляет строку SOCKS5 прокси на сервер |
| `client/requirements.txt` | Python-зависимости: requests[socks], PySocks |
| `deploy.sh` | Скрипт полного автоматического деплоя на Ubuntu |

### Требования

**Ubuntu:**
- Ubuntu 20.04+ (протестировано на 20.04 LTS)
- Два сетевых интерфейса: WAN (интернет) + LAN (к роутеру)
- Доступ к `sudo` (деплой запускается от root)

**Windows:**
- Python 3.8+ с `pip`
- Пакеты: `pip install -r client/requirements.txt`
- Сетевой доступ к локальному IP Ubuntu

**Роутер:**
- Любой Wi-Fi роутер с WAN-портом
- Тип подключения WAN — **DHCP** (автоматически)
- Кабель: WAN-порт роутера → LAN-порт ноутбука

### Деплой

```bash
# На Ubuntu — один раз:
sudo bash deploy.sh
```

Скрипт выполнит:
1. Проверку интернета и системных требований
2. Автоопределение WAN и LAN интерфейсов
3. Разрешение IP Google STUN-сервера (для WebRTC)
4. Установку пакетов: `redsocks`, `dnsmasq`, `iptables-persistent`, `dnsutils`
5. Назначение статического IP `10.0.0.1/24` на LAN-интерфейс (через NetworkManager)
6. Настройку `dnsmasq` как DHCP-сервера (диапазон `10.0.0.100–200`)
7. Применение всех правил `iptables` + `ip6tables` (с сохранением после перезагрузки)
8. Запись `/etc/redsocks.conf` с тремя секциями (TCP redsocks + 2×STUN redudp)
9. Установку Python-окружения, зависимостей, регистрацию и запуск systemd-сервиса

В конце скрипт выводит пошаговую инструкцию по настройке роутера.

### Настройка роутера (один раз)

1. Подключите кабель: `LAN-порт ноутбука → WAN-порт роутера`
2. Подключите телефон/ПК к Wi-Fi роутера
3. Откройте веб-интерфейс роутера (обычно `192.168.0.1` или `192.168.1.1`)
4. Найдите **WAN / Интернет / Тип подключения** → выберите **DHCP (Динамический IP)**
5. Сохраните, подождите 15 секунд

### Клиент (Windows)

```bash
pip install -r client/requirements.txt
python client.py
```

1. Введите локальный IP Ubuntu
2. Вставьте строку SOCKS5 прокси в одном из форматов:
   - `ip:port:логин:пароль`
   - `логин:пароль@ip:port`
3. Нажмите **Check** — проверка прокси (показывает IP, город, ISP; зелёный = США)
4. Нажмите **Route** — весь трафик устройств на роутере идёт через прокси

### API сервера

Сервер слушает на порту `8000`:

```
POST /set_proxy   {"proxy_string": "ip:port:user:pass"}
GET  /status      → {"redsocks": "active", "iface": "enp3s0", "port": 12345}
```

### Как работает подмена WebRTC

Браузеры (Chrome, Firefox) используют протокол STUN (UDP) для обнаружения реального IP за NAT — это «WebRTC-утечка». JackalRouter перехватывает STUN-пакеты в `iptables PREROUTING` (до маршрутизации), DNAT-ит их на локальные `redudp`-слушатели, которые пробрасывают их на STUN-серверы Google **через SOCKS5 прокси**. STUN-сервер видит IP прокси и возвращает его браузеру — WebRTC тоже показывает IP прокси.

### Управление сервисом

```bash
sudo systemctl status jackalrouter
sudo journalctl -u jackalrouter -f
sudo systemctl restart jackalrouter
sudo systemctl restart redsocks
```

# Contributors

- [@MorganWeistling](https://github.com/MorganWeistling)

---

## License

https://t.me/Carl0s_Jackal
