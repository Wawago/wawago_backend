# -*- coding: utf-8 -*-
import hashlib
import string
import random
import logging
logger = logging.getLogger(__name__)

def generate_random_string(size=11, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def generate_jsapi_signature(data, md5=True, final_key=None):
    """微信通用的签名"""
    signature = None
    keys = sorted(data)
    data_str = '&'.join(['%s=%s' % (key, data[key]) for key in keys])
    if final_key:
        data_str += '&key=%s'%final_key
    if md5:
        signature = hashlib.md5(data_str.encode('utf-8')).hexdigest().upper()
    else:
        signature = hashlib.sha1(data_str.encode('utf-8')).hexdigest()
    return signature


def verify_jsapi_signature(data, md5=True, final_key=None):
    """验证微信pay notify的签名"""
    # import pdb; pdb.set_trace()
    m_data = data.copy()
    sign = m_data.pop('sign')
    logger.debug(sign)

    signature = generate_jsapi_signature(m_data, md5, final_key)

    logger.debug(signature)

    if sign == signature:
        return True
    return False