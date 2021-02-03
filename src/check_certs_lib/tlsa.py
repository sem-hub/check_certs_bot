import hashlib
import logging
from OpenSSL import crypto
from typing import Tuple, Union

from check_certs_lib.dns_requests import get_tlsa_record

Null = ''

def generate_tlsa(cert: crypto.X509, usage: int, selector: int, mtype: int) -> bytes:
    if selector == 1:
        dump = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())
    else:
        dump = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)

    if mtype == 0:
        return dump
    if mtype == 1:
        m = hashlib.sha256()
    if mtype == 2:
        m = hashlib.sha512()
    m.update(dump)
    return m.digest()

# Return (error, result)
def check_tlsa(fqdn: str, port: int, cert: crypto.X509, quiet: bool = True
        ) -> Tuple[str, str]:
    logger = logging.getLogger(__name__)
    answer = get_tlsa_record(fqdn, port, quiet=True)

    if len(answer) == 0:
        return ('not found', Null)
    result = False
    for a in answer:
        if a.usage not in (1, 3):
            if not quiet:
                logger.error('Only usage type 1 or 3 are supported')
            continue

        tlsa = generate_tlsa(cert, a.usage, a.selector, a.mtype)
        result = a.cert == tlsa

    if result:
        return (Null, 'OK')
    return ('not match', Null)
