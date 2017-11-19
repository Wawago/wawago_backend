# -*- coding: utf-8 -*-
import logging
logger = logging.getLogger('wechat_sdk')


class WechatException(Exception):
    pass


############# 服务号 ###################
class WechatMPException(WechatException):

    def __init__(self, json_data, url, data={}):
        self.json_data = json_data
        self.url = url
        self.data = data
        logger.error(json_data)
        logger.error(data)
        super(WechatMPException, self).__init__(str(self))

    def __str__(self):
        message = 'wechat mp api error. errcode=%s, errmsg=%s, api url=%s, params=%s.'
        errcode = self.json_data.get('err_code')
        errmsg = self.json_data.get('errmsg')
        msg = message % (errcode, errmsg, self.url, self.data)
        return msg


class WeChatMPMultiPayException(WechatMPException):
    pass


class WeChatMPPayFailException(WechatMPException):
    pass


######### 企业号 #############

class WechatQYException(WechatException):
    def __init__(self, json_data, url, data={}):
        self.json_data = json_data
        self.url = url
        self.data = data
        super(WechatQYException, self).__init__(str(self))

    def __str__(self):
        message = 'wechat qy api error. errcode=%s, errmsg=%s, api url=%s, params=%s.'
        errcode = self.json_data.get('err_code')
        errmsg = self.json_data.get('errmsg')
        msg = message % (errcode, errmsg, self.url, self.data)
        return msg