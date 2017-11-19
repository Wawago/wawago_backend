# -*- coding: utf-8 -*-
import requests
import hashlib
import time
import simplejson
import xmltodict
from .base import WechatBase
from .utils import generate_random_string, generate_jsapi_signature, verify_jsapi_signature
from .exceptions import WechatMPException, WeChatMPMultiPayException, WeChatMPPayFailException

import logging
logger = logging.getLogger('wechat_sdk')


class WechatMP(WechatBase):

    DOMAIN = "api.weixin.qq.com"
    SCHEMA = "https://"

    def __init__(self, app_id, secret, mch_id, mp_key, *args, **kwargs):
        # import pdb; pdb.set_trace()
        self._app_id = app_id
        self._secret = secret
        self._mch_id = mch_id
        self._mp_key = mp_key   
        super(WechatMP, self).__init__(*args, **kwargs)

    def _build_api_url(self, url):
        return "".join([self.SCHEMA, self.DOMAIN, url])

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

    def get_auth_access_token(self, code):
        '''网页授权 access_token'''
        url = "/sns/oauth2/access_token"
        data = {
            'appid': self._app_id,
            'secret': self._secret,
            'code': code,
            'grant_type': "authorization_code",
        }
        return self.api("get", url, data=data)

    def check_auth_access_token_by_open_id(self, access_token, openid):
        ''''''
        url = "/sns/auth"
        data = {
            'access_token': access_token,
            'openid': openid,
            'lang': "zh_CN",
        }
        return self.api("get", url, data=data)

    def get_base_access_token(self):
        url = "/cgi-bin/token"
        data = {
            'appid': self._app_id,
            'secret': self._secret,
            'grant_type': "client_credential",
        }
        return self.api("get", url, data=data)

    def get_user_info(self, access_token, open_id):
        url = "/cgi-bin/user/info"
        data = {
            'access_token': access_token,
            'openid': open_id,
            'lang': "zh_CN",
        }
        return self.api("get", url, data=data)

    def get_jsapi_ticket(self, access_token):

        url = "/cgi-bin/ticket/getticket"
        data = {
            'access_token': access_token,
            'type': 'jsapi',
        }
        return self.api("get", url, data=data)

    # def wechat_jsapi_config(self, url, ticket):
    #     '''微信JS-SDK配置信息 url: 配置信息所使用的 url'''
    #     timestamp = int(time.time())
    #     noncestr = generate_random_string()
    #     # import pdb; pdb.set_trace()
    #     data = {
    #         'jsapi_ticket': ticket,
    #         'noncestr': noncestr,
    #         'timestamp': timestamp,
    #         'url': url,
    #     }
    #     # import pdb; pdb.set_trace()
    #     signature = generate_jsapi_signature(data=data, md5=False)
    #     wx_config = {}
    #     wx_config.update({
    #             # "debug": 'true',
    #             "appId": self._app_id,
    #             "timestamp": timestamp,
    #             "nonceStr": noncestr,
    #             "signature": signature,
    #         })
    #     return wx_config

    def wechat_jsapi_pay(self, ip, order_id, product_name, order_price, notify_url, openid):
        '''微信JS-SDK配置信息 url: 配置信息所使用的url '''
        url = 'https://api.mch.weixin.qq.com/pay/unifiedorder'
        timestamp = int(time.time())
        nonce_str = generate_random_string()
        xml_format = '''
        <xml>
           <appid>{appid}</appid>
           <body>{body}</body>
           <mch_id>{mch_id}</mch_id>
           <nonce_str>{nonce_str}</nonce_str>
           <notify_url>{notify_url}</notify_url>
           <openid>{openid}</openid>
           <out_trade_no>{out_trade_no}</out_trade_no>
           <spbill_create_ip>{spbill_create_ip}</spbill_create_ip>
           <total_fee>{total_fee}</total_fee>
           <trade_type>{trade_type}</trade_type>
           <sign>{sign}</sign>
        </xml>
        '''
        # import pdb; pdb.set_trace()
        data = {
            'appid': self._app_id,
            'mch_id': self._mch_id,
            'nonce_str': nonce_str,
            'body': product_name, #现在每个订单只有一个商品
            'out_trade_no': order_id,
            # 'out_trade_no': int(time.time()),
            'total_fee': order_price,
            'spbill_create_ip': ip,
            'notify_url': notify_url, 
            'trade_type': 'JSAPI',
            'openid': openid,
        }
        logger.debug('wechat_jsapi_pay:')
        logger.debug(data)
        # import pdb; pdb.set_trace()
        signature = generate_jsapi_signature(data=data, md5=True, final_key=self._mp_key)
        logger.debug('signature during pay: %s' % signature)
        data['sign'] = signature
        # import pdb; pdb.set_trace()

        #重要！！！下面那句话如果不加encode('utf-8') 会报错UnicodeEncodeError: 'latin-1' codec can't encode characters
        xml_data = xml_format.format(**data).encode('utf-8') 
        headers = {'Content-Type': 'application/xml;charset=utf-8', 'accept-charset': "UTF-8"}
        res = requests.post(url, data=xml_data, headers=headers)
        response = res.content
        logger.debug('Wechat response:')
        logger.debug(response)
        response_dict = xmltodict.parse(response)
        response_dict = response_dict['xml']

        if 'SUCCESS' not in response_dict['return_code']:
            # msg = response_dict['err_code_des']
            data['error_msg'] = response_dict['return_msg']
            raise WechatMPException(response_dict, url, data)
        result_code = response_dict['result_code']
        if 'FAIL' in result_code:
            err_code = response_dict['err_code']
            err_multi_pay = ['ORDERPAID', 'OUT_TRADE_NO_USED']

            if any(err_code in s for s in err_multi_pay):
                data['error_msg'] = response_dict['err_code_des']
                # msg = msg.encode('latin1') # to solve the unicode problem
                raise WeChatMPMultiPayException(response_dict, url, data)
            else:
                data['error_msg'] = response_dict['err_code_des']
                # msg = msg.encode('latin1')
                raise WeChatMPPayFailException(response_dict, url, data)
        prepay_id = response_dict['prepay_id']
        return prepay_id

    def wechat_jsapi_pay_config(self, prepay_id):
        ''' 微信JS-SDK配置信息 url: 配置信息所使用的utl '''
        # import pdb; pdb.set_trace()
        timestamp = int(time.time())
        nonce_str = generate_random_string()
        data = {
            'appId': self._app_id,
            "timeStamp": timestamp, 
            "nonceStr": nonce_str,
            "signType": 'MD5',
            "package": "prepay_id=%s"%prepay_id,     
        }
        signature = generate_jsapi_signature(data=data, md5=True, final_key=self._mp_key)
        data['paySign'] = signature
        return data

    def check_pay_status(self, order_id):
        '''
        主动查询支付状态

        SUCCESS—支付成功
        REFUND—转入退款
        NOTPAY—未支付
        CLOSED—已关闭
        REVOKED—已撤销（刷卡支付）
        USERPAYING--用户支付中
        PAYERROR--支付失败(其他原因，如银行返回失败)
        '''
        url = 'https://api.mch.weixin.qq.com/pay/orderquery'
        nonce_str = generate_random_string()

        xml_format = '''
        <xml>
           <appid>{appid}</appid>
           <mch_id>{mch_id}</mch_id>
           <nonce_str>{nonce_str}</nonce_str>
           <out_trade_no>{out_trade_no}</out_trade_no>
           <sign>{sign}</sign>
        </xml>
        '''

        data = {
            'appid': self._app_id,
            'mch_id': self._mch_id,
            'nonce_str': nonce_str,
            'out_trade_no': order_id,
        }

        signature = generate_jsapi_signature(data=data, md5=True, final_key=self._mp_key)
        logger.debug('signature during pay: %s' % signature)
        data['sign'] = signature
        # import pdb; pdb.set_trace()

        #重要！！！下面那句话如果不加encode('utf-8') 会报错UnicodeEncodeError: 'latin-1' codec can't encode characters
        xml_data = xml_format.format(**data).encode('utf-8') 
        headers = {'Content-Type': 'application/xml;charset=utf-8', 'accept-charset': "UTF-8"}
        res = requests.post(url, data=xml_data, headers=headers)
        response = res.content
        response_dict = xmltodict.parse(response)
        response_dict = response_dict['xml']
        if 'SUCCESS' not in response_dict['return_code']:
            raise WechatMPException(response_dict, url, data)
        result_code = response_dict['result_code']
        if 'FAIL' in result_code:
            raise WechatMPException(response_dict, url, data)
        trade_state = response_dict['trade_state']
        if 'SUCCESS' or 'FINISH' in trade_state:
            return {'code': 0, 'message': response_dict}
        else:
            return {'code': -1, 'message': trade_state}

    def get_wechat_app_session_key(self, code):
        # https://mp.weixin.qq.com/debug/wxadoc/dev/api/api-login.html#wxloginobject
        # appid=APPID&secret=SECRET&js_code=JSCODE&grant_type=authorization_code
        # 获取微信小程序的 获取微信小程序的 登录信息, 包含 open_id, session_key, union_id
        url = "/sns/jscode2session"
        data = {
            "appid": self._app_id,
            "secret": self._secret,
            "js_code": code,
            "grant_type": "authorization_code"
        }
        return self.api("get", url, data=data)

    def get_wechat_app_login_info_by_code(self, code):
        # https://mp.weixin.qq.com/debug/wxadoc/dev/api/api-login.html#wxloginobject
        # appid=APPID&secret=SECRET&js_code=JSCODE&grant_type=authorization_code
        # 获取微信小程序的 登录信息, 包含 open_id, session_key, union_id
        url = "/sns/jscode2session"
        data = {
            "appid": self._app_id,
            "secret": self._secret,
            "js_code": code,
            "grant_type": "authorization_code"
        }
        result = self.api("get", url, data=data)
        logger.debug("get_wechat_app_login_info_by_code")
        logger.debug(result)
        result_new = {
            "code": result.get("code"),
            "open_id": result.get("openid"),
            "union_id": result.get("unionid")
        }
        if result.get('message'):
            result_new.update({
                'message': result.get('message')
            })
        return result_new
