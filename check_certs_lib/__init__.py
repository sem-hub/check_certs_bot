'''
A library to work with SSL certificates, check them, makeing SSL connections,
DNS requests (with DNSSEC checks on request),
output the certifications as a text, etc.
'''
__version__ = '5.0.7'

# Check python version. We need 3.9+
import sys

if sys.version_info < (3, 9):
    raise ImportError('This library requires Python 3.9+')