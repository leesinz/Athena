import base64
import hashlib
import hmac
import json
import time

import requests


def lark_notification(key, secret, content):
    url = 'https://open.feishu.cn/open-apis/bot/v2/hook/' + key
    headers = {"Content-Type": "application/json"}
    timestamp = str(int(time.time()))
    send_content = {
        "text": content
    }
    data = {
        "timestamp": timestamp,
        "msg_type": "text",
        "content": json.dumps(send_content)
    }
    if secret:
        sign = gen_sign(timestamp, secret)
        data['sign'] = sign
    resp = requests.post(url, headers=headers, json=data)
    print(resp.text)


def gen_sign(timestamp, secret):
    # 拼接timestamp和secret
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    hmac_code = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    # 对结果进行base64处理
    sign = base64.b64encode(hmac_code).decode('utf-8')
    return sign
