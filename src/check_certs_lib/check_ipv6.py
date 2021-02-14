'''Check if IPv6 stack configured and work.'''

from check_certs_lib.dns_requests import get_dns_request
from check_certs_lib.get_cert_from_server import get_cert_from_server


def check_ipv6_work() -> bool:
    '''Check if IPv6 stack configured and work'''
    yandex_ipv6 = get_dns_request('yandex.ru', 'AAAA')
    if len(yandex_ipv6) == 0:
        return False
    err, cert = get_cert_from_server('yandex.ru', str(yandex_ipv6[0]),
            443, 'https')
    if err:
        return False

    return True
