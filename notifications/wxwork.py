import requests


def wxwork_notification(key, content):
    url = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=' + key
    headers = {"Content-Type": "application/json"}
    data = {
        "msgtype": "text",
        "text": {
            "content": content
        }
    }
    requests.post(url, headers=headers, json=data)

