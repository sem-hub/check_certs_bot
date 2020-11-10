import datetime
from pytz import UTC
from os import sys, path

work_dir = path.dirname(path.abspath(__file__))
sys.path.append(work_dir)

from escape_markdown import escape_markdown

def decode_generalized_time(gt):
    return datetime.datetime.strptime(gt.decode('utf8'), '%Y%m%d%H%M%SZ').replace(tzinfo=UTC)

def list_of_tuples(indent: str, lt: tuple):
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
            text.append('%s%s: %s' % (indent, d[name].decode('utf8'), val.decode('utf8')))
        else:
            text.append('%s%s: %s' % (indent, name.decode('utf8'), val.decode('utf8')))

    return '\n'.join(map(str, text))

def x509_alt_names(indent: str, st: str):
    text = list()
    for s in st.split(','):
        s = s.replace(' ', '')
        s = s.replace(':', ': ')
        text.append('%s%s' % (indent, s))

    return '\n'.join(map(str, text))

def cert_to_text(x509: crypto.X509):
    text = list()
    issued_dt = decode_generalized_time(x509.get_notBefore())
    expired_dt = decode_generalized_time(x509.get_notAfter())
    now_aware = datetime.datetime.utcnow().replace(tzinfo=UTC)

    if x509.has_expired():
        text.append('The certificate has expired %d days ago' %
                                    abs((expired_dt - now_aware).days))

    text.append('   *Cert ID*: %X' % x509.get_serial_number())
    text.append('   *Issuer*:')
    text.append(list_of_tuples('      ',
                    x509.get_issuer().get_components()))
    text.append('   *Issued*: %s'% issued_dt.strftime('%b %d %H:%M:%S %Y %Z'))
    text.append('     days ago: %d' % (now_aware - issued_dt).days)
    text.append('   *Expired*: %s' % expired_dt.strftime('%b %d %H:%M:%S %Y %Z'))
    text.append('     days more: %d' % (expired_dt - now_aware).days)
    text.append('   *subject*:')
    text.append(escape_markdown(list_of_tuples('      ',
                                    x509.get_subject().get_components())))

    for i in range(x509.get_extension_count()):
        # XXX debug
        #print(x509.get_extension(i).get_short_name())
        if x509.get_extension(i).get_short_name() == b'subjectAltName':
            text.append('   *subjectAltName*:')
            text.append(escape_markdown(x509_alt_names('      ',
                                x509.get_extension(i)._subjectAltNameString())))

    return '\n'.join(map(str, text))
