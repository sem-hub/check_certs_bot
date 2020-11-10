import re

def is_valid_fqdn(fqdn):
    if len(fqdn) > 255:
        return False
    if fqdn.find('.') == -1:
        return False
    allowed = re.compile('(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
    return all(allowed.match(x) for x in fqdn.split('.'))
