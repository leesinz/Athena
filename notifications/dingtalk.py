from dingtalkchatbot.chatbot import DingtalkChatbot


def dingtalk_notification(access_token, secret, content):
    webhook = 'https://oapi.dingtalk.com/robot/send?access_token=' + access_token
    xiaoding = DingtalkChatbot(webhook, secret)
    xiaoding.send_text(msg=content)
