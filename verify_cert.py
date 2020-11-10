import certifi
import pem
from OpenSSL import crypto

def verify_cert(certs):
    error = None
    store = crypto.X509Store()
    if type(certs) == list:
        cert = certs.pop(0)
        # Recursive check all certificates in the chain
        for i in range(len(certs)):
            err = verify_cert(certs[i])
            if not err:
                store.add_cert(certs[i])
    else:
        cert = certs

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
