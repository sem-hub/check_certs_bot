import datetime
import socket
import timeout_decorator
from OpenSSL import SSL, crypto

from check_certs_lib.verify_cert import verify_cert

TIMEOUT = 5

@timeout_decorator.timeout(TIMEOUT)
def do_handshake_with_timeout(conn):
    conn.do_handshake()

# Return: (err, list(x509))
def get_chain_from_server(hostname: str, addr: str, port: int, proto: str) -> (str, list):
    context = SSL.Context(method=SSL.SSLv23_METHOD)

    # open plain connection
    s_type = socket.AF_INET
    if ':' in addr:
        s_type = socket.AF_INET6
    s = socket.socket(s_type)
    s.settimeout(TIMEOUT)

    conn = SSL.Connection(context=context, socket=s)
    try:
        conn.connect((addr, port))
    except Exception as msg:
        return (f'{addr}: Connection error: {str(msg)}', None)

    try:
        # Send extracommands if required by proto. Ignore server answer.
        if proto == 'smtp':
            s.recv(500)
            s.send(b'EHLO gmail.com\r\n')
            s.recv(500)
            s.send(b'STARTTLS\r\n')
            s.recv(500)
        if proto == 'imap':
            s.recv(500)
            s.send(b'. STARTTLS\r\n')
            s.recv(500)
        if proto == 'ftp':
            s.recv(500)
            s.send(b'AUTH TLS\r\n')
            s.recv(500)
        if proto == 'pop3':
            s.recv(500)
            s.send(b'STLS\r\n')
            s.recv(500)
    except Exception as err:
        return (f'send/recv error: {str(err)}', None)

    try:
        conn.setblocking(1)
        conn.set_tlsext_host_name(hostname.encode())
        do_handshake_with_timeout(conn)
    except (SSL.Error, timeout_decorator.TimeoutError) as err:
        conn.close()
        return (f'{addr}: SSL do_handshake error: {str(err)}', None)
    # Get unverified certificate in binary form
    chain = conn.get_peer_cert_chain()
    conn.close()
    if not chain:
        return(f'{addr}: Get certificate chain error', None)

    return (None, chain)

# Return: (err, x509)
def get_cert_from_server(hostname: str, addr: str, port: int, proto: str) -> (str, crypto.X509):
    (error, chain) = get_chain_from_server(hostname, addr, port, proto)
    if error:
        return (error, None)
    return (None, chain[0])
