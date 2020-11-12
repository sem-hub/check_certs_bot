import certifi
import datetime
import dns.resolver
import hashlib
import pem
from pytz import UTC
from os import sys, path
from OpenSSL import crypto
from ocspchecker import ocspchecker

work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)

from cert_to_text import decode_generalized_time
from dns_requests import get_dns_request

def get_days_before_expired(cert: crypto.X509):
    expired_dt = decode_generalized_time(cert.get_notAfter())
    now_aware = datetime.datetime.utcnow().replace(tzinfo=UTC)
    return (expired_dt - now_aware).days

def get_domains_from_cert(cert: crypto.X509):
    domains = set()
    # Look first onto commonName
    domains.add(cert.get_subject().commonName)
    for i in range(cert.get_extension_count()):
        if cert.get_extension(i).get_short_name() == b'subjectAltName':
            alt_names = cert.get_extension(i)._subjectAltNameString()
            if ',' in alt_names:
                for ds in alt_names.split(', '):
                    domains.add(ds.replace('DNS:',''))
            else:
                domains.add(alt_names.replace('DNS:',''))

    return domains

def match_domain(fqdn: str, cert: crypto.X509):
    # get domains list from the certificate
    domains = get_domains_from_cert(cert)
    for d in domains:
        if fqdn == d:
            return True
        if '*' in fqdn:
            rx= '^'+d.replace('.','\.').replace('*','[^\.]+')+'$'
            re.compile(rx)
            if re.match(fqdn):
                return True
    return False

def verify_cert(certs_to_check):
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

# XXX
#    store.set_flags(crypto.X509StoreFlags.X509_STRICT |
#                        crypto.X509StoreFlags.CB_ISSUER_CHECK)
    store_ctx = crypto.X509StoreContext(store, cert)
    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError as err:
        error = err.args[0][2]+': '+str(cert.get_subject())

    return error

def check_ocsp(cert_chain: list):
    cert_str_list = list()

    for cert in cert_chain:
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        cert_str_list.append(cert_pem.decode())

    try:
        ocsp_url = ocspchecker.extract_ocsp_url(cert_str_list)
    except Exception as err:
        return str(err)

    try:
        ocsp_request = ocspchecker.build_ocsp_request(cert_str_list)
    except Exception as err:
        return str(err)

    try:
        ocsp_response = ocspchecker.get_ocsp_response(ocsp_url, ocsp_request)
    except Exception as err:
        return str(err)

    try:
        ocsp_result = ocspchecker.extract_ocsp_result(ocsp_response)
    except Exception as err:
        return str(err)

    return ocsp_result.replace('OCSP Status: ', '')

def check_tlsa(fqdn: str, port: int, cert: crypto.X509):
    rr_str = '_'+str(port)+'._tcp.'+fqdn+'.'
    dname = dns.name.from_text(rr_str)
    answer = get_dns_request(dname, 'TLSA')

    result = False
    for a in answer:
        if a.usage != 3:
            print('Only usage type 3 is supported')
            continue

        if a.selector == 1:
            dump = crypto.dump_publickey(crypto.FILETYPE_ASN1,
                                              cert.get_pubkey())
        else:
            dump = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)

        if a.mtype == 0:
            result = a.cert == dump
        else:
            if a.mtype == 1:
                m = hashlib.sha256()
            if a.mtype == 2:
                m = hashlib.sha512()
            m.update(dump)
            result = a.cert == m.digest()

    return result
