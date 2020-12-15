import dns.resolver
import logging

def check_fqdn(fqdn: str) -> bool:
    try:
        dname = dns.name.from_text(fqdn)
    except EmptyLabel:
        return False
    return True

def get_all_dns(fqdn: str, only_ipv4: bool = False, only_ipv6: bool = False, only_first: bool = False) -> list:
    # fqdn must be checked with check_fqdn() before
    dname = dns.name.from_text(fqdn)

    if only_ipv4:
        a1 = list()
    else:
        a1 = get_dns_request(dname, 'AAAA')
    if only_ipv6:
        a2 = list()
    else:
        a2 = get_dns_request(dname, 'A')

    r = list()
    for rdata in a1+a2:
        r.append(rdata.to_text())
        if only_first:
            break
    return r

def get_dns_request(dname: str, rtype: str, quiet=True) -> list:
    a = list()
    try:
        answers = dns.resolver.resolve(dname, rtype)
    except dns.resolver.NXDOMAIN:
        if not quiet:
            logging.warning('No DNS record %s found for %s' % (rtype,dname))
        return []
    except dns.resolver.NoAnswer:
        pass
    else:
        for rdata in answers:
            a.append(rdata)
    return a

def get_tlsa_record(fqdn: str, port: int) -> list:
    rr_str = '_'+str(port)+'._tcp.'+fqdn+'.'
    dname = dns.name.from_text(rr_str)

    return get_dns_request(dname, 'TLSA')
