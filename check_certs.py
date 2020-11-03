#!/usr/bin/env python3

from __future__ import print_function
import argparse
import datetime
import dns.resolver
import socket
import ssl
import sys
import OpenSSL
from pytz import UTC

def get_all_dns(dname):
    a1 = get_dns_request(dname, 'AAAA')
    a2 = get_dns_request(dname, 'A')

    r = []
    for rdata in a1+a2:
        r.append(rdata.to_text())
    return r

def get_dns_request(dname, rtype):
    a = []
    try:
        answers = dns.resolver.resolve(dname, rtype)
    except dns.resolver.NXDOMAIN:
        print('No DNS record %s found for %s' % (rtype,fqdn))
        sys.exit(0)
    except dns.resolver.NoAnswer:
        pass
    else:
        for rdata in answers:
            a.append(rdata)
    return a

def decode_generalized_time(gt):
    return datetime.datetime.strptime(gt.decode('utf8'), '%Y%m%d%H%M%SZ').replace(tzinfo=UTC)

def decode_normal_date(gt):
    return datetime.datetime.strptime(gt, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=UTC)

def print_tuple(indent, tup):
    for i in range(0, len(tup)):
        new_tup = ()
        if len(tup[i]) == 1:
            (new_tup, ) = tup[i]
        else:
            new_tup = tup[i]
        (name, val) = new_tup
        print('%s%s: %s' % (indent, escape_markdown(name), escape_markdown(val)))

def print_list_of_tuples(indent, lt):
    d = {'C': 'countryName',
         'O': 'organizationName',
         'ST': 'stateOrProvinceName',
         'L': 'localityName',
         'OU': 'organizationUnitName',
         'CN': 'commonName'
        }
    for (name, val) in lt:
        if name in d.keys():
            print('%s%s: %s' % (indent, d[name].decode('utf8'), escape_markdown(val.decode('utf8'))))
        else:
            print('%s%s: %s' % (indent, name.decode('utf8'), escape_markdown(val.decode('utf8'))))

def print_x509_alt_names(indent, str):
    for s in str.split(','):
        s = s.replace(' ', '')
        s = s.replace(':', ': ')
        print('%s%s' % (indent, escape_markdown(s)))

# DISABLED now
def escape_markdown(msg):
    m = str(msg)
    m = m.replace('[', '\\[')
    m = m.replace('_', '\\_')
    m = m.replace('*', '\\*')
    m = m.replace('`', '\\`')
    #return m
    return msg

def check_cert_problem(a):
    pem_cert = ssl.get_server_certificate(a)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)

    issued_dt = decode_generalized_time(x509.get_notBefore())
    expired_dt = decode_generalized_time(x509.get_notAfter())
    now_aware = datetime.datetime.utcnow().replace(tzinfo=UTC)

    if print_id:
        print('ID: %X' % x509.get_serial_number())

    if x509.has_expired():
        print('%s: The certificate has expired %d days ago' % (a[0],
                                    abs((expired_dt - now_aware).days)))

    if not quiet:
        print('Bad certificate:')
        print('   *Cert ID*: %0.36X' % x509.get_serial_number())
        print('   *Issuer*:')
        print_list_of_tuples('      ', x509.get_issuer().get_components())
        print('   *Issued*: %s'% issued_dt.strftime('%b %d %H:%M:%S %Y %Z'))
        print('     days ago: %d' % (now_aware - issued_dt).days)
        print('   *Expired*: %s' % expired_dt.strftime('%b %d %H:%M:%S %Y %Z'))
        print('     days more: %d' % (expired_dt - now_aware).days)
        print('   *subject*:')
        print_list_of_tuples('      ', x509.get_subject().get_components())
        for i in range(0, x509.get_extension_count()-1):
            #print(x509.get_extension(i).get_short_name())
            if x509.get_extension(i).get_short_name() == 'subjectAltName':
                print('   *subjectAltName*:')
                print_x509_alt_names('      ', x509.get_extension(i)._subjectAltNameString())

parser = argparse.ArgumentParser()
parser.add_argument('fqdn', nargs=1)
parser.add_argument('proto', nargs='?')
parser.add_argument('port', nargs='?', type=int)
parser.add_argument('--debug', action='store_true')
parser.add_argument('--quiet', action='store_true')
parser.add_argument('--print-id', action='store_true')
parser.add_argument('--warn-before-expired', type=int, default=5)
args = parser.parse_args()
fqdn = args.fqdn[0]
debug = args.debug
quiet = args.quiet
print_id = args.print_id
will_expired = args.warn_before_expired
if args.proto != None:
    proto = args.proto
else:
    proto = 'https'
if args.port == None:
    if proto == 'plain':
        print('Port is mandatory for plain protocol')
        sys.exit(1)
    if proto == 'smtp':
        port = 25
    else:
        port = 443
else:
    port = args.port

if not quiet:
    print('proto=%s fqdn=%s port=%d' % (proto, fqdn, port))

dname = dns.name.from_text(fqdn)

addresses = []

if proto == 'smtp':
    if not quiet:
        print('MX records for %s:' % fqdn)
    for rdata in get_dns_request(dname, 'MX'):
        mx_host = rdata.exchange.to_text()[:-1]
        if not quiet:
            print('  %s' % mx_host)
        for addr in get_all_dns(rdata.exchange):
            addresses.append((mx_host,addr))

# if we don't have addresses from MX records
if len(addresses) == 0:
    for addr in get_all_dns(dname):
        addresses.append((fqdn,addr))

if len(addresses) == 0:
    print('No address records found for %s' % fqdn)
    sys.exit(0)
else:
    if not quiet:
        print('%d DNS address[es] found for %s:' % (len(addresses), fqdn))

context = ssl.create_default_context()
cert0 = {}
for addr in addresses:
    if debug:
        print('%s: %s' % addr)
    s_type = socket.AF_INET
    if ':' in addr[1]:
        s_type = socket.AF_INET6
    s = socket.socket(s_type)
    s.settimeout(3)
    if proto == 'smtp':
        try:
            s.connect((addr[1],port))
        except Exception as msg:
            print('%s (%s): SMTP Connection error: %s' % (addr,
                                        escape_markdown(str(msg))))
            continue

        s.recv(1000)
        s.send(b'EHLO gmail.com\n')
        s.recv(1000)
        s.send(b'STARTTLS\n')
        s.recv(1000)
        try:
            conn = context.wrap_socket(s, server_hostname=addr[0])
        except Exception as msg:
            print('STARTTLS error: %s' % escape_markdown(msg))
            continue
        cert = conn.getpeercert()
        s.close()
        if cert == None:
            print('Get certification error')
        if not quiet:
            print('Connection to SMTP is OK')
    else:
        conn = context.wrap_socket(s, server_hostname=fqdn)
        try:
            conn.connect((addr[1],port))
        except Exception as msg:
            if debug:
                print('MSG: %s' % escape_markdown(msg))
            if 'certificate verify failed' in str(msg):
                check_cert_problem((addr[1],port))
            else:
                print('%s:%d: Connection error: %s' % (addr[1], port, 
                                            escape_markdown(str(msg))))
            continue
        else:
            if not quiet:
                print('Connection to %s:%d is OK' % (addr[1], port))
            cert = conn.getpeercert()
            conn.close()
    if not cert0:
        cert0 = cert
    else:
        if cert != cert0:
            print('Certificate is differ')
        else:
            if not quiet:
                print('Certificate is OK')

if bool(cert0):
    issued_dt = decode_normal_date(cert0['notBefore'])
    expired_dt = decode_normal_date(cert0['notAfter'])
    now_aware = datetime.datetime.utcnow().replace(tzinfo=UTC)

    if print_id:
        print('ID: %s' % cert0['serialNumber'])

    if not quiet:
        print('Certificate:')
        print('   *Cert ID*: %s' % cert0['serialNumber'])
        print('   *Issuer*:')
        print_tuple('      ', cert0['issuer'])
        print('   *Issued*: %s' % issued_dt.strftime('%b %d %H:%M:%S %Y %Z'))
        print('     days ago: %d' % (now_aware - issued_dt).days)
        print('   *Expired*: %s' % expired_dt.strftime('%b %d %H:%M:%S %Y %Z'))
        print('     days more: %d' % (expired_dt - now_aware).days)
        print('   *subject*:')
        print_tuple('      ', cert0['subject'])
        print('   *subjectAltName*:')
        print_tuple('      ', cert0['subjectAltName'])

    expired_after = (expired_dt - now_aware).days
    if expired_after <= will_expired:
        print('Certificate will expire after %d days' % expired_after)

