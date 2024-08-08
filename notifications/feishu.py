import base64
import hashlib
import hmac
import time

import requests


def gen_sign(timestamp, secret):
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    hmac_code = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    sign = base64.b64encode(hmac_code).decode('utf-8')
    return sign


def feishu_notification(webhook, secret, content):
    webhook_url = 'https://open.feishu.cn/open-apis/bot/v2/hook/' + webhook
    timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "timestamp": timestamp,
        "msg_type": "text",
        "content": {
            "text": content
        }
    }
    if secret:
        data['sign'] = gen_sign(timestamp, secret)
    requests.post(webhook_url, json=data, headers=headers)
