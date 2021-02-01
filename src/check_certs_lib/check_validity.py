import re
import socket
from urllib.parse import urlparse

def is_valid_fqdn(fqdn: str) -> bool:
    if fqdn is None or len(fqdn) > 255:
        return False
    if fqdn.find('.') == -1:
        return False
    allowed = re.compile(r'(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
    return all(allowed.match(x) for x in fqdn.split('.'))

# Return: (error, protocol, fqdn, port)
def parse_and_check_url(url_str: str) -> (str, str, str, str):
    if '://' not in url_str:
        return (f'URL error: {url_str}\n', '', '', '')

    url = urlparse(url_str)
    scheme = url.scheme
    fqdn = url.hostname
    try:
        port = url.port
    except ValueError:
        return (f'port number error: {url_str}\n', '', '', '')
    if port is None:
        try:
            port = socket.getservbyname(scheme, 'tcp')
        except OSError:
            return (f'Unknown protocol: {scheme}\n', '', '', '')
    if port < 1 or port > 65535:
        return (f'Bad port number: {port}\n', '', '', '')

    if scheme == '':
        return (f'URL parse error: {url_str}\n', '', '', '')

    if not is_valid_fqdn(fqdn):
        return (f'Hostname parse error: {fqdn}\n', '', '', '')

    return ('', scheme, fqdn, port)
