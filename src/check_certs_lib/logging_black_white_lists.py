'''
White/Black lists implementation for logging.
'''

import logging

class Whitelist(logging.Filter):
    '''
    Set a white list as Filter for logging.
    '''
    def __init__(self, *whitelist):
        self.whitelist = [logging.Filter(name) for name in whitelist]

    def filter(self, record):
        return any(f.filter(record) for f in self.whitelist)

class Blacklist(logging.Filter):
    '''
    Set a black list as Filter for logging.
    '''
    def __init__(self, *blacklist):
        self.blacklist = [logging.Filter(name) for name in blacklist]

    def filter(self, record):
        return not any(f.filter(record) for f in self.blacklist)

def add_filter_to_all_handlers(filter_list):
    '''
    This function adds filters to all handlers started from 'root'.
    '''
    for handler in logging.root.handlers:
        handler.addFilter(filter_list)
