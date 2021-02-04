'''
Set of functions for checking and verifying X509 certificates.
'''

import datetime
import re
from typing import List, Set, Union

import certifi
import pem
from pytz import UTC
from OpenSSL import crypto

from check_certs_lib.cert_to_text import decode_generalized_time, strip_subject


def get_days_before_expired(cert: crypto.X509) -> int:
    '''Calcaulate number of days before a certificate expire.'''
    expired_dt = decode_generalized_time(cert.get_notAfter())
    now_aware = datetime.datetime.utcnow().replace(tzinfo=UTC)
    return (expired_dt - now_aware).days

def get_domains_from_cert(cert: crypto.X509) -> Set[str]:
    '''
    Get domains list from a certificate.
    Return: set of domains as strings.
    '''
    domains = set()
    # Look first onto commonName
    domains.add(cert.get_subject().commonName)
    for i in range(cert.get_extension_count()):
        if cert.get_extension(i).get_short_name() == b'subjectAltName':
            alt_names = str(cert.get_extension(i))
            if ',' in alt_names:
                for line in alt_names.split(', '):
                    domains.add(line.replace('DNS:', ''))
            else:
                domains.add(alt_names.replace('DNS:', ''))

    return domains

def match_domain(fqdn: str, cert: crypto.X509) -> bool:
    '''
    Look for matching the FQDN in domains from X509 certificate.
    Return: a boolian.
    '''
    domains = get_domains_from_cert(cert)
    for domain in domains:
        if fqdn == domain:
            return True
        if '*' in domain:
            rxp = '^' + domain.replace('.',r'\.').replace('*',r'[^\.]+') + '$'
            rec = re.compile(rxp)
            if rec.match(fqdn):
                return True
    return False

def verify_cert(certs_to_check: Union[List[crypto.X509], crypto.X509]) -> str:
    '''
    Main function to check certification validating.
    Get: list of X509 or one element X509
    Return: error or '' if certificati is OK
    '''
    error: str = ''
    store = crypto.X509Store()
    if isinstance(certs_to_check, list):
        certs = certs_to_check.copy()
        cert = certs.pop(0)
        # Recursive check all certificates in the chain
        for crt in certs:
            err = verify_cert(crt)
            if not err:
                store.add_cert(crt)
    else:
        cert = certs_to_check

    # Read CA cetrs from a bundle
    with open(certifi.where(), 'rb') as ca_f:
        raw_ca = ca_f.read()
    for ca_cert in pem.parse(raw_ca):
        store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, str(ca_cert)))

# Need we very strict checking flags?
#    store.set_flags(crypto.X509StoreFlags.X509_STRICT |
#                        crypto.X509StoreFlags.CB_ISSUER_CHECK)
    store_ctx = crypto.X509StoreContext(store, cert)
    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError as err:
        error = err.args[0][2] + ': ' + strip_subject((cert.get_subject()))

    return error
