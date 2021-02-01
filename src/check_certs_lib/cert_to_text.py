import datetime
from pytz import UTC
from OpenSSL import crypto

# Text markups
def need_bold(flag: bool):
    def helper(text: str) -> str:
        if flag:
            return '<b>' + text + '</b>'
        else:
            return text
    return helper

def need_italic(flag: bool):
    def helper(text: str) -> str:
        if flag:
            return '<i>' + text + '</i>'
        else:
            return text
    return helper

def need_strike(flag: bool):
    def helper(text: str) -> str:
        if flag:
            return '<s>' + text + '</s>'
        else:
            return text
    return helper

def need_code(flag: bool):
    def helper(text: str) -> str:
        if flag:
            return '<code>' + text + '</code>'
        else:
            return text
    return helper

def need_pre(flag: bool):
    def helper(text: str) -> str:
        if flag:
            return '<pre>' + text + '</pre>'
        else:
            return text
    return helper

def strip_subject(subj) -> str:
    res = str(subj)
    res = res.replace('<', '')
    return res.replace('>', '')

def decode_generalized_time(gt: bytes) -> str:
    return datetime.datetime.strptime(gt.decode('utf8'), '%Y%m%d%H%M%SZ').replace(tzinfo=UTC)

def list_of_tuples(indent: str, lt: tuple) -> str:
    text = list()
    d = {'C': 'countryName',
         'O': 'organizationName',
         'ST': 'stateOrProvinceName',
         'L': 'localityName',
         'OU': 'organizationUnitName',
         'CN': 'commonName'
        }
    for (name, val) in lt:
        if name in d.keys():
            text.append(indent + d[name].decode('utf8') + ': ' + val.decode('utf8'))
        else:
            text.append(indent + name.decode('utf8') + ': ' + val.decode('utf8'))

    return '\n'.join(map(str, text))

def x509_alt_names(indent: str, st: str) -> str:
    text = list()
    for s in st.split(','):
        s = s.replace(' ', '')
        s = s.replace(':', ': ')
        text.append(f'{indent}{s}')

    return '\n'.join(map(str, text))

def cert_to_text(x509: crypto.X509, need_markup: bool = False) -> str:
    b = need_bold(need_markup)
    text = list()
    issued_dt = decode_generalized_time(x509.get_notBefore())
    expired_dt = decode_generalized_time(x509.get_notAfter())
    now_aware = datetime.datetime.utcnow().replace(tzinfo=UTC)

    if x509.has_expired():
        text.append('The certificate has expired %d days ago' %
                                    abs((expired_dt - now_aware).days))

        text.append(f'   {b("Cert ID")}: {x509.get_serial_number():X}')
    text.append(f'   {b("Issuer")}:')
    text.append(list_of_tuples('      ',
                    x509.get_issuer().get_components()))
    text.append(f'   {b("Issued")}: {issued_dt.strftime("%b %d %H:%M:%S %Y %Z")}')
    text.append(f'     days ago: {(now_aware - issued_dt).days}')
    text.append(f'   {b("Expired")}: {expired_dt.strftime("%b %d %H:%M:%S %Y %Z")}')
    text.append(f'     days more: {(expired_dt - now_aware).days}')
    text.append(f'   {b("subject")}:')
    text.append(list_of_tuples('      ', x509.get_subject().get_components()))

    for i in range(x509.get_extension_count()):
        if x509.get_extension(i).get_short_name() == b'subjectAltName':
            text.append(f'   {b("subjectAltName")}:')
            text.append(x509_alt_names('      ', str(x509.get_extension(i))))

    return '\n'.join(map(str, text))
