'''
Set of functions to make a SSL request and get X.509 certificate.
For some protocols it sends an extra commands. An exapmle:
EHLO/STARTTLS commands for SMTP.
'''

import socket
from typing import Optional

from OpenSSL import SSL, crypto
import timeout_decorator


TIMEOUT = 5
NULL = ''
NoResult: list = []

@timeout_decorator.timeout(TIMEOUT)
def do_handshake_with_timeout(conn: SSL.Connection):
    '''
    A stock do_handshake() can't make stop on timeout. It hangs forever.
    This function using timeout_decorator to change this behaviour.
    '''
    conn.do_handshake()

def get_chain_from_server(hostname: str, addr: str, port: int, proto: str
        ) -> tuple[str, list[crypto.X509]]:
    '''
    Get full certificates chain from a server. It respects timeouts.
    Get:
    hostname - for SNI we need a full server name (FQDN).
    addresss - IP address of server as string.
    port - a port as integer.
    proto - protocol name (https, smtp etc.). It's need to know if we need
            to send extra commands or not. If we don't need to send extra
            commands it means we alrerady have SSL connection after connect().
    Return: tuple(error, list(X509))
    '''
    context = SSL.Context(method=SSL.SSLv23_METHOD)

    # open plain connection
    s_type = socket.AF_INET
    if ':' in addr:
        s_type = socket.AF_INET6
    sock = socket.socket(s_type)
    sock.settimeout(TIMEOUT)

    conn = SSL.Connection(context=context, socket=sock)
    try:
        conn.connect((addr, port))
    except Exception as msg:
        return (f'{addr}: Connection error: {str(msg)}', NoResult)

    try:
        # Send extracommands if required by proto. Ignore server answer.
        if proto == 'smtp':
            sock.recv(500)
            sock.send(b'EHLO gmail.com\r\n')
            sock.recv(500)
            sock.send(b'STARTTLS\r\n')
            sock.recv(500)
        if proto == 'imap':
            sock.recv(500)
            sock.send(b'. STARTTLS\r\n')
            sock.recv(500)
        if proto == 'ftp':
            sock.recv(500)
            sock.send(b'AUTH TLS\r\n')
            sock.recv(500)
        if proto == 'pop3':
            sock.recv(500)
            sock.send(b'STLS\r\n')
            sock.recv(500)
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

    return (NULL, chain)

def get_cert_from_server(hostname: str, addr: str, port: int, proto: str
        ) -> tuple[str, Optional[crypto.X509]]:
    '''
    Get only one certificate of the server. It's just a wrapper for
    get_chain_from_server()[0].

    Return: tuple(error, x509 or None)
    '''
    (error, chain) = get_chain_from_server(hostname, addr, port, proto)
    if error:
        return (error, None)
    return (NULL, chain[0])
