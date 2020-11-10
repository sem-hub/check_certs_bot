import datetime
import socket
import sys
from OpenSSL import SSL

from os import sys, path

work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)

from verify_cert import verify_cert

def get_chain_from_server(hostname: str, addr: str, port: int, proto: str):
    context = SSL.Context(method=SSL.TLSv1_2_METHOD)

    # open plain connection
    s_type = socket.AF_INET
    if ':' in addr:
        s_type = socket.AF_INET6
    s = socket.socket(s_type)
    s.settimeout(3)

    conn = SSL.Connection(context=context, socket=s)
    try:
        conn.connect((addr, port))
        conn.setblocking(1)
    except Exception as msg:
        return (('Connection error: %s' % str(msg)), None)

    if proto == 'smtp':
        # Send EHLO, STARTTLS. Ignore server answer (XXX).
        s.recv(1000)
        s.send(b'EHLO gmail.com\n')
        s.recv(1000)
        s.send(b'STARTTLS\n')
        s.recv(1000)

    try:
        conn.set_tlsext_host_name(hostname.encode())
        conn.do_handshake()
    except SSL.Error as err:
        conn.close()
        return (('SSL do_handshake error: %s' % str(err)), None)
    # Get unverified certificate in binary form
    chain = conn.get_peer_cert_chain()
    conn.close()
    if not chain:
        return('Get certificate chain error', None)

    return (None, chain)

def get_cert_from_server(hostname: str, addr: str, port: int, proto: str):
    (error, chain) = get_chain_from_server(hostname, addr, port, proto)
    if error:
        return (error, None)
    return (None, chain[0])