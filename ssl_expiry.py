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


checker_writer = PrettyTable()

def host_information(hostname: str) -> [datetime.datetime, datetime.datetime, str, str]:
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    host_info = {       "ip" : '-',
                        "expire-at": '-', 
                        "from": '-', 
                        "organization":'-', 
                        "cert":  '-',
                        "will-expire-in": '-',
                        "output": '-'
                }

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_OPTIONAL
    conn = context.wrap_socket( socket.socket(socket.AF_INET),server_hostname=hostname,)
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(1.5)
    
    
    try:
        conn.connect_ex((hostname, 443))
        host_info["ip"]=conn.getpeername()
        ssl_info = conn.getpeercert()
    except socket.timeout as e:
        host_info["output"] = f'Time-out '
    except Exception as e:
        host_info["output"] = f'ERROR  {e}'
    else:
        host_info["expire-at"]= datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
        host_info["from"]=datetime.datetime.strptime(ssl_info['notBefore'], ssl_date_fmt)       
        host_info["will-expire-in"]=ssl_valid_time_remaining(host_info["expire-at"])
        host_info["organization"]=ssl_info["subject"][0][0][1]
        host_info["cert"]=ssl_info["issuer"][2][0][1] if "commonName" in ssl_info["issuer"][2][0] else ssl_info["issuer"][3][0][1]
        
        try:
            ssl.match_hostname(ssl_info, hostname)
        except ssl.CertificateError as e: 
            host_info["output"] = f'ERROR  {e}'
        else:
            host_info["output"] = "OK"
    finally:
        # parse the string from the certificate into a Python datetime object
        return host_info



def ssl_valid_time_remaining(expires) -> datetime.timedelta:
    """Get the number of days left in a cert's lifetime."""
    return expires - datetime.datetime.utcnow()


def print_output(hostname, host_info, buffer_days: int=30):
    will_expire_in = host_info["will-expire-in"]
    output = hostname + " " + host_info["output"]
    try:
        if will_expire_in < datetime.timedelta(days=0):
            output = f'{hostname} cert expired'
        elif will_expire_in < datetime.timedelta(days=buffer_days):
            output = f'{hostname} cert will expire in {will_expire_in}'
        else:
            output = f'{hostname} cert is fine'
    except Exception:
        pass
    finally:
        print(output)    

def make_csv(fieldnames, data):
    with open(FILE_NAME_CSV,"w", newline='') as ssl_table:
        ssl_writer = csv.writer(ssl_table, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        ssl_writer.writerow(fieldnames)
        for row in data:
            ssl_writer.writerow(row)


if __name__ == '__main__':    

    start = time.time()
    table_ssl = []
    for host in fileinput.input():
        host = host.strip()
        ssl_info= host_information(host)
        print_output(host, ssl_info)
        checker_writer.add_row([host, *list(ssl_info.values())])
        table_ssl.append([host, *list(ssl_info.values())])

    
    make_csv(TABLE_HEADER,table_ssl)
    checker_writer.field_names=TABLE_HEADER
    print(checker_writer)
