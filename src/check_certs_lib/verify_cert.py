import datetime
import re
import pem
import certifi
from pytz import UTC
from OpenSSL import crypto

from check_certs_lib.cert_to_text import decode_generalized_time, strip_subject

def get_days_before_expired(cert: crypto.X509) -> int:
    expired_dt = decode_generalized_time(cert.get_notAfter())
    now_aware = datetime.datetime.utcnow().replace(tzinfo=UTC)
    return (expired_dt - now_aware).days

def get_domains_from_cert(cert: crypto.X509) -> set:
    domains = set()
    # Look first onto commonName
    domains.add(cert.get_subject().commonName)
    for i in range(cert.get_extension_count()):
        if cert.get_extension(i).get_short_name() == b'subjectAltName':
            alt_names = str(cert.get_extension(i))
            if ',' in alt_names:
                for ds in alt_names.split(', '):
                    domains.add(ds.replace('DNS:', ''))
            else:
                domains.add(alt_names.replace('DNS:', ''))

    return domains

def match_domain(fqdn: str, cert: crypto.X509) -> bool:
    # get domains list from the certificate
    domains = get_domains_from_cert(cert)
    for d in domains:
        if fqdn == d:
            return True
        if '*' in d:
            rx= '^' + d.replace('.',r'\.').replace('*',r'[^\.]+') + '$'
            rec = re.compile(rx)
            if rec.match(fqdn):
                return True
    return False

# cert_to_check: list of x509 or one element x509
# return error or None if certificati is OK
def verify_cert(certs_to_check) -> str:
    error = None
    store = crypto.X509Store()
    if type(certs_to_check) == list:
        certs = certs_to_check.copy()
        cert = certs.pop(0)
        # Recursive check all certificates in the chain
        for i in range(len(certs)):
            err = verify_cert(certs[i])
            if not err:
                store.add_cert(certs[i])
    else:
        cert = certs_to_check

    # Read CA cetrs from a bundle
    with open(certifi.where(), 'rb') as f:
        raw_ca = f.read()
    for ca in pem.parse(raw_ca):
        store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, str(ca)))

# XXX Need we very strict checking flags?
#    store.set_flags(crypto.X509StoreFlags.X509_STRICT |
#                        crypto.X509StoreFlags.CB_ISSUER_CHECK)
    store_ctx = crypto.X509StoreContext(store, cert)
    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError as err:
        error = err.args[0][2] + ': ' + strip_subject((cert.get_subject()))

    return error
