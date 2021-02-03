from typing import Tuple
from OpenSSL import crypto
from ocspchecker import ocspchecker

Null = ''

# Return (error, result)
def check_ocsp(cert_chain: list) -> Tuple[str, str]:
    cert_str_list: list = []

    for cert in cert_chain:
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        cert_str_list.append(cert_pem.decode())

    try:
        ocsp_url = ocspchecker.extract_ocsp_url(cert_str_list)
    except Exception as err:
        return (str(err), Null)

    try:
        ocsp_request = ocspchecker.build_ocsp_request(cert_str_list)
    except Exception as err:
        return (str(err), Null)

    try:
        ocsp_response = ocspchecker.get_ocsp_response(ocsp_url, ocsp_request)
    except Exception as err:
        return (str(err), Null)

    try:
        ocsp_result = ocspchecker.extract_ocsp_result(ocsp_response)
    except Exception as err:
        return (str(err), Null)

    return (Null, ocsp_result.replace('OCSP Status: ', ''))
