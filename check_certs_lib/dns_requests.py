'''DNS utilities.'''

import logging

import dns.dnssec
import dns.rcode
import dns.resolver


# timeout for dns queries
TIMEOUT = 5

def check_fqdn(fqdn: str) -> bool:
    '''
    Check FQDN with dnspython function. It prevent us from an exceptions in
    get_dns_request() because of bad FQDN.
    '''
    try:
        dns.name.from_text(fqdn)
    except Exception:
        return False
    return True

def get_all_dns(fqdn: str, only_ipv4: bool = False, only_ipv6: bool = False,
        only_first: bool = False) -> list:
    '''
    Get all DNS addresses for this FQDN.
    Besides FQDN argument it takes a few flags:
    only_ipv4, only_ipv6 and only_first. These flags explained in check_cert().

    Return: list of IP addresses or an empty list if not found any.
    '''
    # fqdn must be checked with check_fqdn() before
    dname = dns.name.from_text(fqdn)

    if only_ipv4:
        ipv6: list = []
    else:
        ipv6 = get_dns_request(dname, 'AAAA')
    if only_ipv6:
        ipv4: list = []
    else:
        ipv4 = get_dns_request(dname, 'A')

    res: list = []
    for rdata in ipv6 + ipv4:
        res.append(rdata.to_text())
        if only_first:
            break
    return res

def get_dns_request(dname: str, rtype: str) -> list:
    '''
    Make arbitrary DNS request.
    Get arguments:
    dname - FQDN.
    rtype - request type (A, AAAA, MX etc.).

    Return: list of RR records (addresses or FQDNs for MX request etc.).
    '''
    logger = logging.getLogger(__name__)
    result: list = []
    answers: list = []
    try:
        answers = dns.resolver.resolve(dname, rtype)
    except dns.resolver.NXDOMAIN:
        logger.debug('No DNS record %s found for %s', rtype, dname)
        return []
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    else:
        for rdata in answers:
            result.append(rdata)
    return result

def get_authority_ns_for(dname: str) -> dict[str, list[str]]:
    '''
    Get list of IP addresses for authority DNS server for this domain.
    Need for get_dnssec_request().

    Returns: dict[zone] -> autority servers' adresses for the zone
            only one elemeint in the dictionary always
    '''
    logger = logging.getLogger(__name__ + '.get_authority_ns_for')
    dlevel = dname.split('.')
    dlevel.reverse()
    default_resolver = dns.resolver.get_default_resolver()
    nameservers = default_resolver.nameservers

    authority: dict[str, list] = {}
    sdomain: str = ''
    for sublevel in dlevel:
        sdomain = sublevel + '.' + sdomain
        logger.debug(sdomain)
        query = dns.message.make_query(sdomain, dns.rdatatype.NS)
        response = None
        try:
            response = dns.query.udp_with_fallback(query, nameservers[0],
                    timeout=TIMEOUT)
        except Exception as err:
            logger.debug(str(err))
            break
        i = 1
        while response[0].rcode() != dns.rcode.NOERROR and i < len(nameservers):
            try:
                response = dns.query.udp_with_fallback(query, nameservers[i],
                        timeout=TIMEOUT)
            except Exception as err:
                logger.debug(str(err))
                break
            i += 1
        # We tried all nameservers and got errors for each
        if response[0].rcode() != dns.rcode.NOERROR:
            logger.debug('All DNS queried and all returned error for %s',
                    dname)
            return authority

        rrset = None
        if len(response[0].authority) > 0:
            rrset = response[0].authority[0]
        else:
            rrset = response[0].answer[0]

        ns: list[str] = []
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.NS:
                aserver = rr.target
                logger.debug('%s is authoritative for %s', aserver, sdomain)
                for ns_addr in default_resolver.resolve(aserver).rrset:
                    ns.append(ns_addr.to_text())
        if len(ns) > 0:
            nameservers = ns
            authority.clear()
            authority[sdomain] = ns
        # end for
    return authority

def get_dnssec_request(dname: str, rtype: str) -> list:
    '''
    Get any DNS request with DNSSEC checking.
    See get_dns_request for arguments and return value.
    '''
    logger = logging.getLogger(__name__ + '.get_dnssec_request')
    ns_list = get_authority_ns_for(dname)
    zone = list(ns_list.keys())[0]
    # Get DNSKEY for zone
    request = dns.message.make_query(zone, dns.rdatatype.DNSKEY,
            want_dnssec=True)
    nsaddr = ns_list[zone]
    response = None
    try:
        response = dns.query.udp_with_fallback(request, nsaddr[0],
                timeout=TIMEOUT)
    except Exception as err:
        logger.debug(str(err))
        return []
    i = 1
    # Try all servers if any error occured
    while response[0].rcode() != dns.rcode.NOERROR and \
            len(response[0].answer) != 2 and \
            i < len(nsaddr):
        try:
            response = dns.query.udp_with_fallback(request, nsaddr[i],
                    timeout=TIMEOUT)
        except Exception as err:
            logger.debug(str(err))
            break
        i += 1
    if response[0].rcode() != dns.rcode.NOERROR:
        logger.debug('zone %s resolve error', zone)
        return []
    if len(response[0].answer) != 2:
        logger.debug('zone %s is not signed', zone)
        return []
    answer = response[0].answer
    dnskey = answer[0]

    # check zone signature
    zname = dns.name.from_text(zone)
    try:
        dns.dnssec.validate(dnskey, answer[1], {zname: dnskey})
    except Exception as err:
        logger.debug('zone %s signature error: %s', zone, err)
        return []

    name = dns.name.from_text(dname)
    request = dns.message.make_query(name, rtype, want_dnssec=True)
    try:
        response = dns.query.udp_with_fallback(request, nsaddr[0],
                timeout=TIMEOUT)
    except Exception as err:
        logger.debug(str(err))
        return []
    i = 1
    # Try all servers if any error occured
    while response[0].rcode() != dns.rcode.NOERROR and \
            len(response[0].answer) < 2 and \
            i < len(nsaddr):
        response = dns.query.udp_with_fallback(request, nsaddr[i])
        i += 1
    if response[0].rcode() != dns.rcode.NOERROR:
        logger.debug('%s resolve error', dname)
        return []
    if len(response[0].answer) < 2:
        logger.debug('%s is not signed', dname)
        return []
    answer = response[0].answer
    try:
        dns.dnssec.validate(answer[0], answer[1], {zname: dnskey})
    except Exception as err:
        logger.debug('"%s" record for %s signature error: err', rtype,
                dname, err)
        return []

    result: list = []
    for rr in answer:
        if rr.rdtype == dns.rdatatype.from_text(rtype):
            result.append(rr.to_rdataset()[0])
    return result

def get_tlsa_record(fqdn: str, port: int) -> list:
    '''
    Construct and make DNS request for a TLSA record.
    Return: list of TLSA records or an empty list.
    '''
    rr_str = '_' + str(port) + '._tcp.' + fqdn

    # Ask for TLSA only with DNSSEC request
    return get_dnssec_request(rr_str, 'TLSA')
