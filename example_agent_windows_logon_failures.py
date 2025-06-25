#! python3.11
# -*- coding: utf-8 -*-
"""
pfSense Agents Alias — Windows 4625 Watcher
-------------------------------------------------------------------------------
* Monitora falhas de logon (Evento 4625) no log Security.
* Agrupa por IP e bloqueia no pfSense via Agents Alias API quando um endereço
  atinge `fail_limit` falhas dentro da janela `window_min`.
* Persistência:
      · pf4625.ini   — parâmetros de conexão e política (gerado no 1.º run)
      · pf4625_bans.xml — registro dos bloqueios: IP, início, expiração, contagem
* Tabela em tempo real: IP | Qtde | Desde | Até (indeterminado se permanente).
-------------------------------------------------------------------------------

* Monitors logon failures (Event 4625) in the Security log.
* Groups by IP and blocks in pfSense via Agents Alias ​​API when an address
reaches `fail_limit` failures within the `window_min` window.
* Persistence:
· pf4625.ini — connection and policy parameters (generated on 1st run)
· pf4625_bans.xml — log of blocks: IP, start, expiration, count
* Real-time table: IP | Qty | From | To (undetermined if permanent).


Autor  : Josias L. Gonçalves · josiaslg@bsd.com.br | josiaslg@cloudunix.com.br
Licença: BSD-3-Clause
Atual. : 25-Jun-2025 05:50 BRT
"""

# Dependências (instalar uma vez — Prompt/Admin):
#   pip install --upgrade pip
#   pip install pywin32 requests
#   python -m pywin32_postinstall -install

import os
import sys
import re
import time
import configparser
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from collections import defaultdict

import requests
import win32evtlog                     # pywin32
import urllib3                         # para silenciar warning TLS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --------------------------------------------------------------------------- #
# Arquivos                                                                    #
# --------------------------------------------------------------------------- #
BASE_DIR   = os.path.dirname(__file__)
CFG_PATH   = os.path.join(BASE_DIR, 'pf4625.ini')
BAN_PATH   = os.path.join(BASE_DIR, 'pf4625_bans.xml')

# --------------------------------------------------------------------------- #
# INI padrão (criado no 1.º run)                                              #
# --------------------------------------------------------------------------- #
DEFAULT_INI = {
    'pfSense': {
        'prefix'     : 'https',      # http | https
        'host'       : '192.0.2.1',  # IP / FQDN do pfSense
        'port'       : '443',        # Porta WebGUI
        'ignore_ssl' : '0',          # 1 = desativa verificação TLS
        'token'      : 'CHANGEME'    # Bearer Token da API
    },
    'Policy': {
        'fail_limit'    : '3',       # Falhas para bloquear
        'window_min'    : '60',      # Janela p/ contagem (min)
        'penalty_hours' : '24',      # 0 = permanente
        'loop_seconds'  : '60'       # Livre entre ciclos (s)
    }
}

# --------------------------------------------------------------------------- #
# Regex para IP                                                               #
# --------------------------------------------------------------------------- #
IPV4_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
IPV6_RE = re.compile(r'^[0-9a-fA-F:]{3,39}$')

# --------------------------------------------------------------------------- #
# Constantes de log                                                           #
# --------------------------------------------------------------------------- #
LOG_NAME = 'Security'
EVENT_ID = 4625   # An account failed to log on

# --------------------------------------------------------------------------- #
# Carregar ou criar INI                                                       #
# --------------------------------------------------------------------------- #
cfg = configparser.ConfigParser()
if not os.path.isfile(CFG_PATH):
    cfg.read_dict(DEFAULT_INI)
    with open(CFG_PATH, 'w', encoding='utf-8') as f:
        cfg.write(f)
    print(f'[i] {CFG_PATH} criado — configure e execute novamente.')
    sys.exit(0)

cfg.read(CFG_PATH, encoding='utf-8')
PFS, POL = cfg['pfSense'], cfg['Policy']

FAIL_LIMIT  = int(POL.get('fail_limit',    3))
WINDOW_MIN  = int(POL.get('window_min',   60))
PENALTY_H   = int(POL.get('penalty_hours', 0))
LOOP_SEC    = int(POL.get('loop_seconds', 60))

BASE_URL = f"{PFS['prefix']}://{PFS['host']}:{PFS['port']}/agents_alias_api.php"
REQ_OPTS = {
    'headers': {'Authorization': f"Bearer {PFS['token']}"},
    'verify' : False if PFS.getboolean('ignore_ssl') else True,
    'timeout': 10
}

# --------------------------------------------------------------------------- #
# Funções de XML (bans)                                                       #
# --------------------------------------------------------------------------- #
def load_bans():
    if not os.path.isfile(BAN_PATH):
        ET.ElementTree(ET.Element('blocked')).write(BAN_PATH)
    tree = ET.parse(BAN_PATH)
    return tree, tree.getroot()

def save_bans(tree):
    tree.write(BAN_PATH, encoding='utf-8', xml_declaration=True)

def is_blocked(root, ip):
    return root.find(f"./entry[@ip='{ip}']") is not None

def add_ban(root, ip, expires_iso, count):
    ET.SubElement(
        root, 'entry',
        ip=ip,
        added=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        expires=expires_iso,
        count=str(count)
    )

def remove_expired_bans(tree, root):
    now = datetime.now(timezone.utc)
    changed = False
    for entry in list(root):
        expires = entry.get('expires')
        if expires != 'never' and now >= datetime.fromisoformat(expires):
            ip = entry.get('ip')
            if unblock_ip(ip):
                root.remove(entry)
                changed = True
    if changed:
        save_bans(tree)

def print_ban_table(root):
    if not list(root):
        print('(nenhum IP bloqueado)\n')
        return
    header = f'{"IP":<39}  {"Qtde":>5}  {"Desde":<25}  {"Até":<25}'
    print(header)
    print('-'*len(header))
    for entry in sorted(root, key=lambda e: e.get('added')):
        ip    = entry.get('ip')
        qtd   = entry.get('count')
        added = entry.get('added')
        exp   = entry.get('expires')
        exp   = 'indeterminado' if exp == 'never' else exp
        print(f'{ip:<39}  {qtd:>5}  {added:<25}  {exp:<25}')
    print()

# --------------------------------------------------------------------------- #
# API pfSense                                                                 #
# --------------------------------------------------------------------------- #
def block_ip(ip):
    ts_now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    params = {'action': 'add', 'ip': ip, 'ts': ts_now}
    try:
        requests.get(BASE_URL, params=params, **REQ_OPTS).raise_for_status()
        return True
    except Exception as e:
        print(f'[!] Falha ao bloquear {ip}: {e}')
        return False

def unblock_ip(ip):
    params = {'action': 'del', 'ip': ip}
    try:
        requests.get(BASE_URL, params=params, **REQ_OPTS).raise_for_status()
        print(f'[−] {ip} removido do alias.')
        return True
    except Exception as e:
        print(f'[!] Falha ao remover {ip}: {e}')
        return False

# --------------------------------------------------------------------------- #
# Lê eventos 4625                                                             #
# --------------------------------------------------------------------------- #
def fetch_failed_logons(last_rec=0):
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    h = win32evtlog.OpenEventLog(None, LOG_NAME)
    events = win32evtlog.ReadEventLog(h, flags, 0)

    hits = defaultdict(list)
    newest_rec = last_rec

    for ev in events:
        if ev.EventID != EVENT_ID or ev.RecordNumber <= last_rec:
            continue
        newest_rec = max(newest_rec, ev.RecordNumber)

        ts = ev.TimeGenerated.replace(tzinfo=timezone.utc)
        ip = next((s.strip() for s in ev.StringInserts
                   if IPV4_RE.fullmatch(s or '') or IPV6_RE.fullmatch(s or '')),
                  None)
        if ip:
            hits[ip].append(ts)

    win32evtlog.CloseEventLog(h)
    return hits, newest_rec

# --------------------------------------------------------------------------- #
# Loop principal                                                              #
# --------------------------------------------------------------------------- #
def main():
    tree, root = load_bans()
    last_record = 0

    print('\n### Estado atual dos bloqueios:')
    print_ban_table(root)

    while True:
        remove_expired_bans(tree, root)

        hits, last_record = fetch_failed_logons(last_record)
        for ip, stamps in hits.items():
            stamps.sort()
            if len(stamps) >= FAIL_LIMIT and \
               (stamps[-1] - stamps[0]).total_seconds() <= WINDOW_MIN * 60 and \
               not is_blocked(root, ip):

                exp_iso = 'never' if PENALTY_H == 0 else (
                    datetime.now(timezone.utc).replace(microsecond=0) +
                    timedelta(hours=PENALTY_H)
                ).isoformat()

                if block_ip(ip):
                    add_ban(root, ip, exp_iso, len(stamps))
                    save_bans(tree)
                    alvo = 'indeterminado' if exp_iso == 'never' else exp_iso
                    print(f'[+] {ip} bloqueado ({len(stamps)} falhas) → desbloqueia: {alvo}\n')

                    print('### Resumo atualizado:')
                    print_ban_table(root)

        time.sleep(LOOP_SEC)

# --------------------------------------------------------------------------- #
# Execução                                                                    #
# --------------------------------------------------------------------------- #
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrompido pelo usuário.')
