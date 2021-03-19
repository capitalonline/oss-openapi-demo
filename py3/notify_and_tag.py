# coding: utf-8
import base64
import hmac
import time
import urllib.parse as parse
import uuid
from hashlib import sha1

import requests
import xmltodict as xmlparse

# 使用美国站点或者亚洲站点本地需要加入如下host
'''
38.83.106.196  cdsapi-us.capitalonline.net
164.52.39.148  cdsapi-asia.capitalonline.net
'''

# default
OPENAPI_URL = 'http://cdsapi.capitalonline.net/oss'
# OPENAPI_URL = 'http://cdsapi-us.capitalonline.net/oss'
# OPENAPI_URL = 'http://cdsapi-asia.capitalonline.net/oss'

# 标签和事件通知目前只有法兰克福节点支持
Endpoint = 'oss-fra.cdsgss.com'

# OPENAPI USER AK SK
a_key = ''
s_key = ''


class PayloadType:
    XML = 'xml'
    JSON = 'json'


def encode_query_param(query_param):
    _query_str = ''
    if query_param:
        _query_str = parse.urlencode(query_param)
    return _query_str


def percent_encode(string):
    """将特殊转义字符替换"""
    res = parse.quote(string, '')
    res = res.replace('+', '%20')
    res = res.replace('*', '%2A')
    res = res.replace('%7E', '~')
    return res


def signature(action, ak, access_key_secret, method, url, param={}):
    """
    @params: action: 接口动作
    @params: ak: ak值
    @params: access_key_secret: ak秘钥
    @params: method: 接口调用方法(POST/GET)
    @params: param: 接口调用Query中参数(非POST方法Body中参数)
    @params: url: 接口调用路径
    @return: 请求的url可直接调用
    """
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    D = {
        'Action': action,
        'AccessKeyId': ak,
        'SignatureMethod': 'HMAC-SHA1',
        'SignatureNonce': str(uuid.uuid1()),
        'SignatureVersion': "1.0",
        "Timestamp": timestamp,
        'Version': '2019-08-08',
    }
    if param:
        D.update(param)
    sortedD = sorted(D.items(), key=lambda x: x[0])
    canstring = ''
    for k, v in sortedD:
        canstring += '&' + percent_encode(k) + '=' + percent_encode(v)
    stringToSign = method + '&%2F&' + percent_encode(canstring[1:])
    stringToSign = stringToSign.encode('utf-8')
    access_key_secret = access_key_secret.encode('utf-8')
    h = hmac.new(access_key_secret, stringToSign, sha1)
    signature = base64.encodebytes(h.digest()).strip()
    D['Signature'] = signature
    url = url + '/?' + parse.urlencode(D)
    print(url)
    return url


class OpenAPI(object):
    TagsAction = "DescribeTags"
    NotifyAction = "DescribeNotify"

    def __init__(self, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key

    def get_object_tags(self, bucket, obj):
        '''获取对象tag'''
        method = 'GET'
        url = f'{OPENAPI_URL}/{obj}'
        headers = {
            'Host': f'{bucket}.{Endpoint}'
        }
        param = {'tagging': ''}
        url = signature(self.TagsAction, self.access_key, self.secret_key, method, url, param)
        resp = requests.get(url, headers=headers)
        status = resp.status_code
        data = resp.content.decode('utf-8')
        return status, data

    def add_object_tags(self, bucket, obj, body=None):
        '''增加对象tag'''
        method = 'PUT'
        url = f'{OPENAPI_URL}/{obj}'
        print(url)
        headers = {
            'Host': f'{bucket}.{Endpoint}'
        }
        param = {'tagging': ''}

        if not body:
            body = {
                'Tagging': {
                    'TagSet': {
                        'Tag': [
                            {'Key': 'b', 'Value': 'b'},
                            {'Key': 'c', 'Value': 'c'}
                        ]
                    }
                }
            }

        data = xmlparse.unparse(body, pretty=False)
        url = signature(self.TagsAction, self.access_key, self.secret_key, method, url, param)
        resp = requests.put(url, data=data, headers=headers)
        status = resp.status_code
        data = resp.text
        return status, data

    def del_object_tags(self, bucket, obj):
        '''删除对象tag'''
        method = 'DELETE'
        url = f'{OPENAPI_URL}/{obj}'
        headers = {
            'Host': f'{bucket}.{Endpoint}'
        }
        param = {'tagging': ''}

        url = signature(self.TagsAction, self.access_key, self.secret_key, method, url, param)
        resp = requests.delete(url, headers=headers)
        status = resp.status_code
        data = resp.text
        return status, data

    def get_bucket_tags(self, bucket):
        '''获取桶tag'''
        method = 'GET'
        url = OPENAPI_URL
        headers = {
            'Host': f'{bucket}.{Endpoint}'
        }
        param = {'tagging': ''}

        # 获取签名自动生成请求url
        url = signature(self.TagsAction, self.access_key, self.secret_key, method, url, param)
        resp = requests.get(url, headers=headers)
        status = resp.status_code
        data = resp.text
        return status, data

    def add_bucket_tags(self, bucket):
        '''增加桶tag'''
        method = 'PUT'
        url = OPENAPI_URL
        headers = {
            'Host': f'{bucket}.{Endpoint}'
        }
        param = {'tagging': ''}

        body = {'Tagging': {'TagSet': {
            'Tag': [
                {'Value': 'aa', 'Key': 'aa'},
                {'Value': 'bb', 'Key': 'bb'}
            ]
        }}}
        data = xmlparse.unparse(body, pretty=False)
        url = signature(self.TagsAction, self.access_key, self.secret_key, method, url, param)
        resp = requests.put(url, data=data, headers=headers)
        status = resp.status_code
        data = resp.text
        return status, data

    def del_bucket_tags(self, bucket):
        '''删除桶tag'''
        method = 'DELETE'
        url = OPENAPI_URL
        headers = {
            'Host': f'{bucket}.{Endpoint}'
        }
        param = {'tagging': ''}

        url = signature(self.TagsAction, self.access_key, self.secret_key, method, url, param)
        resp = requests.delete(url, headers=headers)
        status = resp.status_code
        data = resp.text
        return status, data

    def add_notify_config(self, bucket, body=None):
        '''增加事件通知规则'''
        method = 'PUT'
        url = OPENAPI_URL
        headers = {
            'Host': f'{bucket}.{Endpoint}'
        }
        param = {'notification': ''}
        if not body:
            notify1 = {
                'RuleName': 'bbq',
                'Event': 'ObjectCreated:Put',
                'Filter': {
                    'S3Key': {
                        'FilterRule': [
                            {'Name': 'prefix', 'Value': 'dbs'},
                            {'Name': 'prefix', 'Value': 'oas'}
                        ]
                    }
                },
                'Target': {
                    'Type': 'kafka', 'Topic': 'wangwei',
                    'Url': '101.89.76.90:9092',
                    'Token': None, 'UserName': 'admin',
                    'Password': 'admin', 'Version': None
                }
            }
            body = {
                'NotificationConfiguration': {
                    'RuleConfiguration': [notify1]
                }
            }
        data = xmlparse.unparse(body, pretty=False)
        url = signature(self.NotifyAction, self.access_key, self.secret_key, method, url, param)
        resp = requests.put(url, data=data, headers=headers)
        status = resp.status_code
        data = resp.text
        return status, data

    def get_notify_config(self, bucket):
        '''获取事件通知规则'''
        method = 'GET'
        url = OPENAPI_URL
        headers = {
            'Host': f'{bucket}.{Endpoint}'
        }
        param = {'notification': ''}
        url = signature(self.NotifyAction, self.access_key, self.secret_key, method, url, param)
        resp = requests.get(url, headers=headers)
        status = resp.status_code
        data = resp.text
        return status, data


if __name__ == '__main__':
    api = OpenAPI(a_key, s_key)
    bucket = ''
    filename = ''
    print(api.add_object_tags(bucket, filename))
    print(api.get_object_tags(bucket, filename))
    print(api.del_object_tags(bucket, filename))
    print(api.add_bucket_tags(bucket))
    print(api.get_bucket_tags(bucket))
    print(api.del_bucket_tags(bucket))
    print(api.get_notify_config(bucket))
    print(api.add_notify_config(bucket))
