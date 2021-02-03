'''Functions for checking FQDN and URL'''

import re
import socket
from typing import Tuple
from urllib.parse import urlparse


# Some shortenings for return values.
NoResult = ('', '', 0)
Null = ''

def is_valid_fqdn(fqdn: str) -> bool:
    '''
    Check if DNS name (FQDN) is correct

    Return a boolean True or False.
    '''
    if not fqdn or len(fqdn) > 255:
        return False
    if fqdn.find('.') == -1:
        return False
    allowed = re.compile(r'(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
    return all(allowed.match(x) for x in fqdn.split('.'))

def parse_and_check_url(url_str: str) -> Tuple[str, Tuple[str, str, int]]:
    '''
    Parse and check server's URL.

    Return: tuple(error, tuple(protocol, fqdn, port))
    '''
    if '://' not in url_str:
        return (f'URL error: {url_str}\n', NoResult)

    url = urlparse(url_str)
    scheme = str(url.scheme)
    fqdn = str(url.hostname)
    try:
        port = url.port
    except ValueError:
        return (f'port number error: {url_str}\n', NoResult)
    if port is None:
        try:
            port = socket.getservbyname(scheme, 'tcp')
        except OSError:
            return (f'Unknown protocol: {scheme}\n', NoResult)
    if port < 1 or port > 65535:
        return (f'Bad port number: {port}\n', NoResult)

    if scheme == '':
        return (f'URL parse error: {url_str}\n', NoResult)

    if not is_valid_fqdn(fqdn):
        return (f'Hostname parse error: {fqdn}\n', NoResult)

    return (Null, (scheme, fqdn, port))
