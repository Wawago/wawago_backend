# -*- coding: utf-8 -*-
import requests
# import hashlib
import time
import simplejson
import base64
import json
from Crypto.Cipher import AES
import hashlib
from .base import WechatBase

import logging
logger = logging.getLogger(__name__)


class WechatAPP(WechatBase):

    DOMAIN = "api.weixin.qq.com"
    SCHEMA = "https://"

    def __init__(self, app_id, secret, *args, **kwargs):
        # import pdb; pdb.set_trace()
        self._app_id = app_id
        self._secret = secret
        # self._mch_id = mch_id
        # self._mp_key = mp_key   
        super(WechatAPP, self).__init__(*args, **kwargs)

    def _build_api_url(self, url):
        return "".join([self.SCHEMA, self.DOMAIN, url])


def decrypt_wechat_app_data(wechat_app_app_id, sessioin_key, encrypted_data, iv):
    '''
    {
        "openId": "OPENID",
        "nickName": "NICKNAME",
        "gender": GENDER,
        "city": "CITY",
        "province": "PROVINCE",
        "country": "COUNTRY",
        "avatarUrl": "AVATARURL",
        "unionId": "UNIONID",
        "watermark":
        {
            "appid":"APPID",
        "timestamp":TIMESTAMP
        }
    }
    '''

    sessionKey = base64.b64decode(sessioin_key)
    encryptedData = base64.b64decode(encrypted_data)
    iv = base64.b64decode(iv)
    cipher = AES.new(sessionKey, AES.MODE_CBC, iv)
    s = cipher.decrypt(encryptedData)
    temp = s[:-ord(s[len(s)-1:])]
    decrypted = json.loads(temp.decode("utf-8"))
    if decrypted['watermark']['appid'] != wechat_app_app_id:
        raise Exception('Invalid Buffer')
    return decrypted

def verify_raw_data(session_key, raw_data, signature):
    data = raw_data + session_key
    signature2 = hashlib.sha1(data.encode("utf-8")).hexdigest()
    return signature == signature2