#!/bin/env python3

from logging import debug
from requests import get
from sqlite3 import connect, OperationalError
from re import compile


URL = 'http://standards-oui.ieee.org/oui/oui.txt'
DBPATH = '/var/cache/fenrir/'


def updatemacvendors(dbpath=f'{DBPATH}macvendors.sqlite') -> None:
    """ update/create given database with current MAC vendor list

    :param dbpath: path to mac database to be updated/created
    """
    db = connect(dbpath)
    cur = db.cursor()
    cur.execute(
        'CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY, vendor TEXT);')

    macmatch = compile(r'(\S+)\s+\(hex\)\s+(.*)$')
    with get(URL, stream=True) as r:
        for line in r.iter_lines(decode_unicode=True):
            res = macmatch.search(line)
            if not res:
                continue
            cur.execute('INSERT OR REPLACE INTO devices(mac, vendor) values(?, ?)',
                        (res.group(1).replace("-", ":"), res.group(2)))
    db.commit()
    db.close()


def getvendorformac(mac, dbpath=f'{DBPATH}macvendors.sqlite', retrycount=0) -> str:
    """ get vendor name for given mac address

    :param mac: mac address for vendor lookup
    :param dbpath: path for lookup database (default set)
    :param retrycount: counter for automatic vendor download
    """
    try:
        with connect(f'file:{dbpath}?mode=ro', timeout=10, check_same_thread=False, uri=True) as db:
            cursor = db.cursor()
            # magic number 8 = first 6 MAC bytes + 2 spacer bytes
            result = cursor.execute('SELECT vendor FROM devices WHERE mac = ?;', (mac[:8].upper(), )).fetchone()
            if result:
                return result[0]
            return ''
    except OperationalError as e:
        debug(f'unable to connect to vendor database: {e}')
        updatemacvendors()
        if retrycount < 1:
            getvendorformac(mac=mac, dbpath=dbpath, retrycount=1)
        return ''


if __name__ == "__main__":
    updatemacvendors(dbpath=f'{DBPATH}macvendors.sqlite')
