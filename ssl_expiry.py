# Author: Lucas Roelser <roesler.lucas@gmail.com>
# Modified from serverlesscode.com/post/ssl-expiration-alerts-with-lambda/

import datetime
import fileinput
import logging
import os
import socket
import ssl
import time
from prettytable import PrettyTable
import csv
import sys

dt=datetime.datetime.today().strftime("%m%d%y-%H%M%S")
FILE_NAME_TXT=f'ssl-checker-{dt}.txt'
FILE_NAME_CSV=f'ssl-checker-{dt}.csv'
TABLE_HEADER = ["hostname", "IP-host","expire_date", "from", "organization", "cert" , "expire_in", "connectionInfo"]

logger = logging.getLogger('SSLVerify')
checker_writer = PrettyTable()

def ssl_infomation(hostname: str) -> [datetime.datetime, datetime.datetime, str, str]:
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    context = ssl.create_default_context()
    conn = context.wrap_socket( socket.socket(socket.AF_INET),server_hostname=hostname,)
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)

    logger.debug('Connect to {}'.format(hostname))
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    ssl_name = conn.getpeername()
    # parse the string from the certificate into a Python datetime object
    return [ssl_name[0],
            datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt), 
            datetime.datetime.strptime(ssl_info['notBefore'], ssl_date_fmt), 
            ssl_info["subject"][0][0][1], 
            ssl_info["issuer"][3][0][1]]


def ssl_valid_time_remaining(expires) -> datetime.timedelta:
    """Get the number of days left in a cert's lifetime."""
    # logger.debug(
    #     'SSL cert for {} expires at {}'.format(
    #         hostname, expires.isoformat()
    #     )
    # )
    return expires - datetime.datetime.utcnow()


def test_host(hostname: str, buffer_days: int=30): # -> [ssl_inf,will_expire_in, fromDate, commonName, "-"]:
    """Return test message for hostname cert expiration."""
    ssl_info=['-']*5
    will_expire_in = '-'
    error = '-'
    try:
        ssl_info = ssl_infomation(hostname)
        will_expire_in = ssl_valid_time_remaining(ssl_info[1])
    except ssl.CertificateError as e:
        output = f'{hostname} cert error {e}' 
    except ssl.SSLError as e:
        output = f'{hostname} SSL error {e}'
    except socket.timeout as e:
        output = f'{hostname} Time-out '
    except Exception as e:
        output = f'{hostname} ERROR  {e}'
    else:
        if will_expire_in < datetime.timedelta(days=0):
           output = f'{hostname} cert expired'
        elif will_expire_in < datetime.timedelta(days=buffer_days):
            output = f'{hostname} cert will expire in {will_expire_in}'
        else:
            output = f'{hostname} cert is fine'

    finally:
        print(output)
        return [*ssl_info, will_expire_in, output]

def make_csv(fieldnames, data):
    with open(FILE_NAME_CSV,"w", newline='') as ssl_table:
        ssl_writer = csv.writer(ssl_table, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        ssl_writer.writerow(fieldnames)
        for row in data:
            ssl_writer.writerow(row)


if __name__ == '__main__':
    loglevel = os.environ.get('LOGLEVEL', 'INFO')
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(level=numeric_level)
    

    start = time.time()
    table_ssl = []
    for host in fileinput.input():
        host = host.strip()
        logger.debug('Testing host {}'.format(host))
        ssl_info= test_host(host)
        checker_writer.add_row([host, *ssl_info])
        table_ssl.append([host, *ssl_info])

    
    make_csv(TABLE_HEADER,table_ssl)
    checker_writer.field_names=TABLE_HEADER
    print(checker_writer)
    logger.debug('Time: {}'.format(time.time() - start))
