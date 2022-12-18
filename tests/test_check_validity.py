from check_certs_lib.check_validity import (
        is_valid_fqdn,
        parse_and_check_url
        )

def test_is_valid_fqdn():
    assert is_valid_fqdn('ya.ru')
    assert not is_valid_fqdn('plain sting')

def test_parse_and_check_url():
    assert parse_and_check_url('https://ya.ru:777') == ('', ('https', 'ya.ru', 777))
    assert parse_and_check_url('https://ya.ru') == ('', ('https', 'ya.ru', 443))        # default port
    assert parse_and_check_url('plain string') == ('URL error: plain string\n', ('', '', 0))
    assert parse_and_check_url('https://ya.ru:abc') == ('port number error: https://ya.ru:abc\n', ('', '', 0))