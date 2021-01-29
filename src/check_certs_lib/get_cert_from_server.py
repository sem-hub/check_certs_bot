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
def get_chain_from_server(hostname: str, addr: str, port: int, starttls: bool) -> (str, list):
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
        if starttls:
            # Send EHLO, STARTTLS. Ignore server answer (XXX).
            s.recv(1000)
            s.send(b'EHLO gmail.com\n')
            s.recv(1000)
            s.send(b'STARTTLS\n')
            s.recv(1000)
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
def get_cert_from_server(hostname: str, addr: str, port: int, starttls: bool) -> (str, crypto.X509):
    (error, chain) = get_chain_from_server(hostname, addr, port, starttls)
    if error:
        return (error, None)
    return (None, chain[0])
