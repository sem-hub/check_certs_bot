'''
Functions to make TLSA, reques it and check it.
'''

import hashlib
import logging

from OpenSSL import crypto

from check_certs_lib.dns_requests import get_tlsa_record


NULL = ''

def generate_tlsa(cert: crypto.X509, usage: int, selector: int,
        mtype: int) -> bytes:
    '''
    Construct a TLSA record.
    '''
    if selector == 1:
        dump = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())
    else:
        dump = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)

    if mtype == 0:
        return dump
    if mtype == 1:
        sha = hashlib.sha256()
    if mtype == 2:
        sha = hashlib.sha512()
    sha.update(dump)
    return sha.digest()

def check_tlsa(fqdn: str, port: int, cert: crypto.X509) -> tuple[str, str]:
    '''
    Construct TLSA, request DNS TLSA record, compare them.

    Return: tuple(error, result)
    '''
    logger = logging.getLogger(__name__)
    answers = get_tlsa_record(fqdn, port)

    if len(answers) == 0:
        return ('not found', NULL)
    result = False
    for answ in answers:
        if answ.usage not in (1, 3):
            logger.warning('Only usage type 1 or 3 are supported')
            continue

        tlsa = generate_tlsa(cert, answ.usage, answ.selector, answ.mtype)
        result = answ.cert == tlsa

    if result:
        return (NULL, 'OK')
    return ('not match', NULL)
