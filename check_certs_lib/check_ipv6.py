'''Check if IPv6 stack configured and work.'''

from check_certs_lib.dns_requests import get_dns_request
from check_certs_lib.get_cert_from_server import get_cert_from_server

ipv6_work_cached = None
def check_ipv6_work() -> bool:
    '''Check if IPv6 stack configured and work'''
    global ipv6_work_cached
    if ipv6_work_cached is not None:
        return ipv6_work_cached

    yandex_ipv6 = get_dns_request('yandex.ru', 'AAAA')
    if len(yandex_ipv6) == 0:
        return False
    err, cert = get_cert_from_server('yandex.ru', str(yandex_ipv6[0]),
            443, 'https')
    if err:
        ipv6_work_cached = False
        return False

    ipv6_work_cached = True
    return True
