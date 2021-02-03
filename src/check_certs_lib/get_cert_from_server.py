import socket
import timeout_decorator
from OpenSSL import SSL, crypto
from typing import Tuple, List, Union

TIMEOUT = 5
Null = ''
NoResult: list = []

@timeout_decorator.timeout(TIMEOUT)
def do_handshake_with_timeout(conn):
    conn.do_handshake()

# Return: (err, list(x509))
def get_chain_from_server(hostname: str, addr: str, port: int, proto: str
        ) -> Tuple[str, List[crypto.X509]]:
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
        return (f'{addr}: Connection error: {str(msg)}', NoResult)

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
        return (f'send/recv error: {str(err)}', NoResult)

    try:
        conn.setblocking(1)
        conn.set_tlsext_host_name(hostname.encode())
        do_handshake_with_timeout(conn)
    except (SSL.Error, timeout_decorator.TimeoutError) as err:
        conn.close()
        return (f'{addr}: SSL do_handshake error: {str(err)}', NoResult)
    # Get unverified certificate in binary form
    chain = conn.get_peer_cert_chain()
    conn.close()
    if not chain:
        return(f'{addr}: Get certificate chain error', NoResult)

    return (Null, chain)

# Return: (err, x509)
def get_cert_from_server(hostname: str, addr: str, port: int, proto: str
        ) -> Tuple[str, Union[crypto.X509, None]]:
    (error, chain) = get_chain_from_server(hostname, addr, port, proto)
    if error:
        return (error, None)
    return (Null, chain[0])
