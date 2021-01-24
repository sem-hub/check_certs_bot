import logging

from check_certs_lib.check_validity import parse_and_check_url
from check_certs_lib.get_cert_from_server import get_chain_from_server
from check_certs_lib.verify_cert import verify_cert, match_domain, get_days_before_expired
from check_certs_lib.cert_to_text import cert_to_text
from check_certs_lib.escape_markdown import escape_markdown
from check_certs_lib.dns_requests import get_dns_request, check_fqdn, get_all_dns
from check_certs_lib.tlsa import check_tlsa
from check_certs_lib.ocsp import check_ocsp

MAIL_PROTO = ['smtp', 'smtps', 'submission']

def check_cert(url_str: str, flags: dict) -> str:
    # For fast using
    quiet = flags.get('quiet')

    err, scheme, fqdn, port = parse_and_check_url(url_str)
    if err != '':
        return err
    if not check_fqdn(fqdn):
        return f'Host name is invalid: {fqdn}\n'

    logging.debug(f'{scheme} {fqdn} {port}')

    addresses = list()
    message = ''

    if scheme in MAIL_PROTO:
        if not quiet:
            message = message + f'MX records for {fqdn}:\n'
        for rdata in get_dns_request(fqdn, 'MX', quiet):
            mx_host = rdata.exchange.to_text()[:-1]
            if not quiet:
                message = message + f'  {mx_host}\n'
            for addr in get_all_dns(rdata.exchange, flags.get('only_ipv4'),
                    flags.get('only_ipv6'), flags.get('only_one')):
                addresses.append((mx_host,addr))

    # Only smtp protocol needs extra EHLO/STARTTLS commands
    starttls = False
    if scheme == 'smtp':
        starttls = True

    # if we don't have addresses from MX records
    if len(addresses) == 0:
        for addr in get_all_dns(fqdn, flags.get('only_ipv4'), flags.get('only_ipv6'), flags.get('only_one')):
            addresses.append((fqdn,addr))

    if len(addresses) == 0:
        message = message + f'No address records found for {fqdn}\n'
        return message
    else:
        if not quiet:
            message = message + f'{len(addresses)} DNS address[es] found for {fqdn}:\n'

    cert0_id = 0
    for addr in addresses:
        # XXX if not debug
        if not quiet:
            message = message + f'{addr[0]}: {addr[1]}\n'
        error, chain = get_chain_from_server(addr[0], addr[1], port, starttls)
        if error:
            message = message + f'Error: {error}\n'
            continue
        # XXX debug only
        if not quiet:
            message = message + f'Got {len(chain)} certificates in chain\n'
        cert = chain[0]
        is_new_cert = not cert0_id
        if is_new_cert:
            cert0_id = cert.get_serial_number()

        # Do not check the same certificate again
        if not is_new_cert and cert.get_serial_number() == cert0_id:
            if not quiet:
                message = message + 'Certificate is the same\n'
        else:
            if cert.get_serial_number() != cert0_id:
                message = message + 'Certificates are differ\n'

            error = verify_cert(chain)

            if flags.get('print_id'):
                message = message + 'ID: %X\n' % cert.get_serial_number()
            if not quiet:
                message = message + cert_to_text(cert) + '\n'

            # If we have bad certificate here, don't check it for matching
            if error:
                message = message + f'Certificate error: {error}\n'
                continue
            else:
                if not match_domain(fqdn, cert):
                    # XXX print domain list from certificate if verbose or debug
                    message = message + 'Certificate error: Host name ' + \
                            'mismatched with any domain in certificate\n'
                    continue
                else:
                    days_before_expired = get_days_before_expired(cert)
                    if flags.get('warn_before_expired') and \
                        days_before_expired <= flags['warn_before_expired']:
                            message = message + 'Certificate fill expired ' + \
                                f'after {days_before_expired} days\n'
                    else:
                        # ocspcheck can't check only one certificate. It needs a chain
                        if len(chain) > 1 and not flags.get('no_ocsp'):
                            result = check_ocsp(chain)
                            if result != 'GOOD' or not quiet:
                                message = message + f'OCSP check result: *{result}*\n'
                            if result != 'GOOD':
                                continue
                        if not quiet:
                            message = message + 'Certificate is good\n'
            # only good certificate here
            # Run TLSA check if we have TLSA record
            if not flags.get('no_tlsa'):
                res = check_tlsa(fqdn, port, chain[0], quiet)
                if res == 'OK':
                    if not quiet:
                        message = message + 'TLSA is *OK*\n'
                else:
                    if res == 'not found':
                        if not quiet:
                            message = message + f'TLSA is not found. Ignored\n'
                    else:
                        message = message + f'TLSA is *{res}*\n'

    return message
