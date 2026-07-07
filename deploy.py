#!/usr/bin/env python3
"""
JackalRouter — удалённый деплой с клиента (одной командой).

Запуск:   python deploy.py
          (или двойной клик по deploy.bat на Windows)

Что делает:
  1. Спрашивает IP сервера и SSH-логин, проверяет связь.
  2. Отключает пароль sudo на сервере (NOPASSWD) — один раз вводите пароль.
  3. Предлагает выбрать вид деплоя (UBUNTU+ROUTER / RASPBERRY+ROUTER / RASPBERRY+WIFI).
  4. Сам копирует нужные файлы по scp и запускает деплой на сервере.

Требуется: клиент OpenSSH (ssh/scp). На Windows 10/11 он встроен, на Linux/Mac есть.
"""

import os
import sys
import shutil
import subprocess

# ── ANSI-цвета (включаем обработку на Windows 10+) ────────────────────────────
if os.name == "nt":
    os.system("")
R = "\033[0;31m"; G = "\033[0;32m"; Y = "\033[0;33m"
B = "\033[0;34m"; C = "\033[0;36m"; W = "\033[1;37m"; N = "\033[0m"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REMOTE_DIR = "jackalrouter-deploy"           # каталог на сервере (в домашней папке)
SUDOERS    = "/etc/sudoers.d/jackal-nopasswd"

SSH_OPTS = ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]

# Виды деплоя: ключ → (человекочитаемое имя, файл, описание)
DEPLOYS = {
    "1": ("UBUNTU + ROUTER",     "deploy.sh",
          "Ubuntu-ноутбук: интернет по Wi-Fi, раздача по кабелю через тех. роутер"),
    "2": ("RASPBERRY + ROUTER",  "deploy-rpi5.sh",
          "Raspberry Pi: интернет по Wi-Fi, раздача по кабелю через тех. роутер"),
    "3": ("RASPBERRY + WIFI",    "deploy-rpi5-ap.sh",
          "Raspberry Pi = свой Wi-Fi роутер: интернет по кабелю, раздача по Wi-Fi"),
}

# Файлы/папки, которые нужны на сервере для запуска деплоя
PAYLOAD = ["deploy.sh", "deploy-rpi5.sh", "deploy-rpi5-ap.sh", "server"]


def ok(m):   print(f"{G}  ✓ {m}{N}")
def warn(m): print(f"{Y}  ⚠ {m}{N}")
def err(m):  print(f"{R}  ✗ {m}{N}")
def info(m): print(f"{C}  → {m}{N}")


def die(msg, hint=""):
    print(f"\n{R}═══════════════════════════════════════════════{N}")
    print(f"{R}  ОШИБКА: {msg}{N}")
    print(f"{R}═══════════════════════════════════════════════{N}")
    if hint:
        print(f"{Y}  Что делать: {hint}{N}")
    sys.exit(1)


def header():
    print(f"{B}╔══════════════════════════════════════════════╗{N}")
    print(f"{B}║{W}    JackalRouter — Удалённый деплой          {B}║{N}")
    print(f"{B}║{C}  Заливает и запускает всё на сервере сам     {B}║{N}")
    print(f"{B}╚══════════════════════════════════════════════╝{N}\n")


def check_tools():
    for t in ("ssh", "scp"):
        if shutil.which(t) is None:
            die(f"Не найден '{t}' (клиент OpenSSH).",
                "Windows 10/11: Параметры → Приложения → Доп. компоненты → "
                "'Клиент OpenSSH'. Linux/Mac: установите openssh-client.")
    ok("SSH/SCP на месте")


def run_ssh(user, host, remote_cmd, tty=False, check=True, quiet=False):
    """Выполнить команду на сервере. tty=True — для интерактива (пароль sudo,
    вопросы деплоя): подключает живой терминал."""
    cmd = ["ssh"] + SSH_OPTS + (["-t"] if tty else []) + [f"{user}@{host}", remote_cmd]
    kwargs = {}
    if quiet:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    r = subprocess.run(cmd, **kwargs)
    if check and r.returncode != 0:
        return False
    return r.returncode == 0


def run_scp(user, host):
    """Скопировать PAYLOAD в ~/REMOTE_DIR на сервере (относительные пути —
    иначе Windows-путь 'C:\\...' scp примет за host:path)."""
    os.chdir(SCRIPT_DIR)
    missing = [p for p in PAYLOAD if not os.path.exists(p)]
    if missing:
        die(f"Рядом с deploy.py нет: {', '.join(missing)}",
            "Запускайте deploy.py из папки проекта (где лежат deploy.sh и server/).")
    cmd = ["scp"] + SSH_OPTS + ["-r"] + PAYLOAD + [f"{user}@{host}:{REMOTE_DIR}/"]
    return subprocess.run(cmd).returncode == 0


def main():
    header()

    # ── 0. Инструменты ────────────────────────────────────────────────────────
    check_tools()

    # ── 1. Параметры подключения ──────────────────────────────────────────────
    host = ""
    if len(sys.argv) > 1:
        host = sys.argv[1].strip()
    while not host:
        host = input(f"{W}  IP сервера (например 192.168.1.96): {N}").strip()
    user = input(f"{W}  SSH-логин [family]: {N}").strip() or "family"

    print()
    info(f"Проверяю связь с {user}@{host} …  (если попросит пароль — введите)")
    if not run_ssh(user, host, "true", quiet=True):
        die(f"Нет SSH-связи с {user}@{host}.",
            "Проверьте: сервер включён, IP верный, SSH включён (sudo systemctl "
            "enable --now ssh), логин правильный. Если просит пароль — введите его.")
    ok(f"Связь есть: {user}@{host}")

    # ── 2. Отключение пароля sudo (NOPASSWD) ──────────────────────────────────
    print()
    info("Отключаю запрос пароля sudo (NOPASSWD) — возможно, спросит пароль один раз…")
    sudo_setup = (
        f'echo "{user} ALL=(ALL) NOPASSWD:ALL" | sudo tee {SUDOERS} >/dev/null '
        f'&& sudo chmod 440 {SUDOERS} '
        f'&& sudo visudo -cf {SUDOERS}'
    )
    if not run_ssh(user, host, sudo_setup, tty=True):
        die("Не удалось настроить NOPASSWD sudo.",
            "Убедитесь, что пользователь в группе sudo и пароль верный.")
    # проверка: sudo теперь без пароля
    if not run_ssh(user, host, "sudo -n true", quiet=True):
        warn("sudo всё ещё просит пароль — деплой может переспросить его.")
    else:
        ok("sudo без пароля настроен")

    # ── 3. Выбор вида деплоя ───────────────────────────────────────────────────
    print()
    print(f"{W}  Выберите вид деплоя:{N}")
    for k, (name, _f, desc) in DEPLOYS.items():
        print(f"    {G}{k}{N}) {W}{name}{N}")
        print(f"       {C}{desc}{N}")
    choice = ""
    while choice not in DEPLOYS:
        choice = input(f"{W}  Номер [1-3]: {N}").strip()
    name, script, _desc = DEPLOYS[choice]
    ok(f"Выбрано: {name}  ({script})")

    # ── 4. Копирование файлов ─────────────────────────────────────────────────
    print()
    info(f"Копирую файлы в ~/{REMOTE_DIR} на сервере…")
    run_ssh(user, host, f"mkdir -p ~/{REMOTE_DIR}", quiet=True)
    if not run_scp(user, host):
        die("Не удалось скопировать файлы (scp).",
            "Проверьте связь и свободное место на сервере.")
    ok("Файлы скопированы")

    # нормализуем переносы строк (если git выгрузил .sh как CRLF — bash сломается)
    normalize = (
        f"cd ~/{REMOTE_DIR} && "
        f"sed -i 's/\\r$//' *.sh server/*.py server/*.service 2>/dev/null; true"
    )
    run_ssh(user, host, normalize, quiet=True)

    # ── 5. Запуск деплоя ───────────────────────────────────────────────────────
    print()
    print(f"{B}══════════════════════════════════════════════{N}")
    print(f"{W}  Запускаю {name} на сервере…{N}")
    print(f"{B}══════════════════════════════════════════════{N}\n")
    run_cmd = f"cd ~/{REMOTE_DIR} && sudo bash {script}"
    success = run_ssh(user, host, run_cmd, tty=True)

    print()
    if success:
        print(f"{G}╔══════════════════════════════════════════════╗{N}")
        print(f"{G}║{W}        ДЕПЛОЙ ЗАВЕРШЁН                      {G}║{N}")
        print(f"{G}╚══════════════════════════════════════════════╝{N}")
        print(f"{W}  Дальше: откройте клиент JackalRouter, укажите IP {C}{host}{N}")
        print(f"{W}  (или {C}10.0.0.1{N}{W} со стороны Wi-Fi у Pi-AP), вставьте прокси → Route.{N}")
    else:
        err("Деплой завершился с ошибкой — смотрите вывод выше.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}  Прервано пользователем.{N}")
        sys.exit(130)
