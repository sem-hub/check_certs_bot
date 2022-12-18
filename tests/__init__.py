import importlib

print('Find module path')
importlib.find_loader('check_cert_lib', path='..')