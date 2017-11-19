# -*- coding: utf-8 -*-
import requests
import hashlib
import time
import simplejson
import xmltodict
import logging
from core.common_exceptions import HttpMethodNotAllowedException
from .exceptions import WechatMPException, WeChatMPMultiPayException, WeChatMPPayFailException
from .utils import generate_random_string, generate_jsapi_signature


class WechatBase():

    ALLOWED_HTTP_METHOD = ('get', 'post')

    def __init__(self, *args, **kwargs):
        # self._app_id = wechat_conf.get("APP_ID")
        # self._secret = wechat_conf.get("SECRET")
        # self._mch_id = wechat_conf.get("MCH_ID")
        # self._mp_key = wechat_conf.get("MP_KEY")        
        super(WechatBase, self).__init__(*args, **kwargs)

    def _check_http_method(self, http_method):
        if http_method.lower() in self.ALLOWED_HTTP_METHOD:
            return True 
        else:
            raise HttpMethodNotAllowedException

    def _build_api_url(self, url):
        raise NotImplementedError

    def api(self, http_method, url, access_token=None, data={}, **kwargs):
        '''大部分的接口可使用这个api去完成。一小部分不符合规则的api，单独写出来'''
        url = self._build_api_url(url)
        # 添加全局 access_token
        if access_token:
            url = url + "?access_token=%s" % access_token
        self._check_http_method(http_method)
        res = getattr(self, http_method)(url, data, **kwargs)
        result = self._handle_response(res, url, data)
        return result

    def get(self, url, data, **kwargs):
        result = requests.get(url, params=data)
        return result

    def post(self, url, data, **kwargs):
        result = requests.post(url, json=data)
        return result

    def _handle_response(self, result, url, data={}):
        json_data = result.json()
        # 检查返回结果
        if "errcode" in json_data and json_data["errcode"] != 0:
            # raise WechatMPException(json_data, url, data)
            message = "wechat:errcode=%s, errmsg=%s"
            message = message % (json_data.get("errcode"), json_data.get("errmsg"))
            json_data = {"code": -1, "message": message}
        else:
            json_data.update({"code": 0})
        return json_data

    def generate_auth_url(self, callback_url):
        url_list = [
            "https://open.weixin.qq.com/connect/oauth2/authorize?",
            'appid=',
            self._app_id,
            '&redirect_uri=',
            callback_url,
            '&response_type=code&scope=snsapi_base',
        ]
        url_list.append('#wechat_redirect')
        url = ''.join(url_list)
        return url

    def wechat_jsapi_config(self, url, ticket):
        '''微信JS-SDK配置信息 url: 配置信息所使用的 url'''
        timestamp = int(time.time())
        noncestr = generate_random_string()
        # import pdb; pdb.set_trace()
        data = {
            'jsapi_ticket': ticket,
            'noncestr': noncestr,
            'timestamp': timestamp,
            'url': url,
        }
        # import pdb; pdb.set_trace()
        signature = generate_jsapi_signature(data=data, md5=False)
        wx_config = {}
        wx_config.update({
            # "debug": 'true',
            "appId": self._app_id,
            "timestamp": timestamp,
            "nonceStr": noncestr,
            "signature": signature,
        })
        return wx_config
