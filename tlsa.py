import hashlib
from OpenSSL import crypto
from os import sys, path
work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)
from dns_requests import get_tlsa_record

def generate_tlsa(cert: crypto.X509, usage: int, selector: int, mtype: int) -> str:
    if selector == 1:
        dump = crypto.dump_publickey(crypto.FILETYPE_ASN1,
                                          cert.get_pubkey())
    else:
        dump = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)

    if mtype == 0:
        return dump
    else:
        if mtype == 1:
            m = hashlib.sha256()
        if mtype == 2:
            m = hashlib.sha512()
        m.update(dump)
        return m.digest()

def check_tlsa(fqdn: str, port: int, cert: crypto.X509) -> bool:
    answer = get_tlsa_record(fqdn, port)

    result = False
    for a in answer:
        if a.usage != 3:
            #print('Only usage type 3 is supported')
            continue

        tlsa = generate_tlsa(cert, a.usage, a.selector, a.mtype)
        result = a.cert == tlsa

    return result
