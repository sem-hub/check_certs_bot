from check_certs_lib.cert_to_text import (cert_to_text,
                                          datetime_to_user_tz_str,
                                          decode_generalized_time,
                                          need_bold, need_code, need_italic,
                                          need_pre, need_strike, strip_subject)


def check_markup_closure(cl, mark):
    if mark is None:
        if cl('123') == '123':
            return True
        return False
    if cl('123') == f'<{mark}>123</{mark}>':
        return True
    return False
        
def test_need_bold():
    assert check_markup_closure(need_bold(False), None)
    assert check_markup_closure(need_bold(True), 'b')

def test_need_italic():
    assert check_markup_closure(need_italic(False), None)
    assert check_markup_closure(need_italic(True), 'i')

def test_need_strike():
    assert check_markup_closure(need_strike(False), None)
    assert check_markup_closure(need_strike(True), 's')

def test_need_code():
    assert check_markup_closure(need_code(False), None)
    assert check_markup_closure(need_code(True), 'code')

def test_need_pre():
    assert check_markup_closure(need_pre(False), None)
    assert check_markup_closure(need_pre(True), 'pre')

def test_strip_subject():
    assert strip_subject('<123>') == '123'

def test_datetime_to_user_tz_str():
    assert datetime_to_user_tz_str('2022-12-18 18:48:00.0', 4) == '2022-12-18 22:48:00'

def test_decode_generalized_time():
    assert str(decode_generalized_time(b'20221218184800Z')) == '2022-12-18 18:48:00+00:00'
