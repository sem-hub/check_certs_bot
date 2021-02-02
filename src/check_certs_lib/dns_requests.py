import logging
import dns.resolver

# timeout for dns queries
TIMEOUT = 5

def check_fqdn(fqdn: str) -> bool:
    try:
        dns.name.from_text(fqdn)
    except Exception:
        return False
    return True

# Return empty list if not found any
def get_all_dns(fqdn: str, only_ipv4: bool = False, only_ipv6: bool = False,
        only_first: bool = False) -> list:
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
    for rdata in a1 + a2:
        r.append(rdata.to_text())
        if only_first:
            break
    return r

def get_dns_request(dname: str, rtype: str, quiet: bool = True) -> list:
    logger = logging.getLogger(__name__)
    result = list()
    answers = None
    try:
        answers = dns.resolver.resolve(dname, rtype)
    except dns.resolver.NXDOMAIN:
        if not quiet:
            logger.warning(f'No DNS record {rtype} found for {dname}')
        return list()
    except dns.resolver.NoAnswer:
        pass
    else:
        for rdata in answers:
            result.append(rdata)
    return result

# Returns: dict[zone] -> autority servers' adresses for the zone
#                        only one elemeint in the dictionary always
def get_authority_ns_for(dname: str, quiet: bool = True) -> dict:
    logger = logging.getLogger(__name__ + '.get_authority_ns_for')
    # Turn off debug for this function temporarly
    logger.setLevel(logging.INFO)
    dlevel = dname.split('.')
    dlevel.reverse()
    default_resolver = dns.resolver.get_default_resolver()
    nameservers = default_resolver.nameservers

    authority = dict()
    sdomain = ''
    for sublevel in dlevel:
        sdomain = sublevel + '.' + sdomain
        logger.debug(sdomain)
        query = dns.message.make_query(sdomain, dns.rdatatype.NS)
        response = None
        try:
            response = dns.query.udp(query, nameservers[0], timeout=TIMEOUT)
        except Exception as err:
            logger.error(str(err))
            break
        i = 1
        while response.rcode() != dns.rcode.NOERROR and i < len(nameservers):
            try:
                response = dns.query.udp(query, nameservers[i], timeout=TIMEOUT)
            except Exception as err:
                logger.error(str(err))
                break
            i += 1
        # We tried all nameservers and got errors for each
        if response.rcode() != dns.rcode.NOERROR:
            if not quiet:
                logger.debug(f'All DNS queried and all returned error for {dname}')
            return authority

        rrset = None
        if len(response.authority) > 0:
            rrset = response.authority[0]
        else:
            rrset = response.answer[0]

        ns = list()
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.NS:
                aserver = rr.target
                logger.debug(f'{aserver} is authoritative for {sdomain}')
                for r in default_resolver.resolve(aserver).rrset:
                    ns.append(r.to_text())
        if len(ns) > 0:
            nameservers = ns
            authority.clear()
            authority[sdomain] = ns
    return authority

def get_dnssec_request(dname: str, rtype: str, quiet: bool = True) -> list:
    logger = logging.getLogger(__name__ + '.get_dnssec_request')
    ns_list = get_authority_ns_for(dname, quiet)
    zone = list(ns_list.keys())[0]
    # Get DNSKEY for zone
    request = dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True)
    nsaddr = ns_list[zone]
    response = None
    try:
        response = dns.query.udp(request, nsaddr[0], timeout=TIMEOUT)
    except Exception as err:
        logger.error(str(err))
        return list()
    i = 1
    # Try all servers if any error occured
    while response.rcode() != dns.rcode.NOERROR and \
          len(response.answer) != 2 and \
          i < len(nsaddr):
        try:
            response = dns.query.udp(request, nsaddr[i], timeout=TIMEOUT)
        except Exception as err:
            logger.error(str(err))
            break
        i += 1
    if response.rcode() != dns.rcode.NOERROR:
        if not quiet:
            logger.error(f'zone {zone} resolve error')
        return list()
    if len(response.answer) != 2:
        if not quiet:
            logger.error(f'zone {zone} is not signed')
        return list()
    answer = response.answer
    dnskey = answer[0]

    # check zone signature
    zname = dns.name.from_text(zone)
    try:
        dns.dnssec.validate(dnskey, answer[1], {zname: dnskey})
    except dns.dnssec.ValidationFailure:
        if not quiet:
            logger.error(f'zone {zone} signature error')
        return list()

    name = dns.name.from_text(dname)
    request = dns.message.make_query(name, rtype, want_dnssec=True)
    try:
        response = dns.query.udp(request, nsaddr[0], timeout=TIMEOUT)
    except Exception as err:
        logger.debug(str(err))
        return list()
    i = 1
    # Try all servers if any error occured
    while response.rcode() != dns.rcode.NOERROR and \
          len(response.answer) < 2 and \
          i < len(nsaddr):
        response = dns.query.udp(request, nsaddr[i])
        i += 1
    if response.rcode() != dns.rcode.NOERROR:
        if not quiet:
            logger.error(f'{dname} resolve error')
        return list()
    if len(response.answer) < 2:
        if not quiet:
            logger.error(f'{dname} is not signed')
        return list()
    answer = response.answer
    try:
        dns.dnssec.validate(answer[0], answer[1], {zname: dnskey})
    except dns.dnssec.ValidationFailure:
        if not quiet:
            logger.error(f'\'{rtype}\' record for {dname} signature error')
        return list()

    result = list()
    for rr in answer:
        if rr.rdtype == dns.rdatatype.from_text(rtype):
            result.append(rr.to_rdataset()[0])
    return result

def get_tlsa_record(fqdn: str, port: int, quiet: bool = True) -> list:
    rr_str = '_' + str(port) + '._tcp.' + fqdn

    # Ask for TLSA only with DNSSEC request
    return get_dnssec_request(rr_str, 'TLSA', quiet)
