from config import cfg
from dingtalk import dingtalk_notification
from wxwork import wxwork_notification
from email import email_notification


def send_notifications(subject, message, content):
    notify = cfg['notify']

    if notify['email']['enable']:
        email_notification(notify['email']['smtp_server'], notify['email']['smtp_port'], notify['email']['username'], notify['email']['password'], notify['email']['from'], notify['email']['to'], subject, message)

    if notify['wxwork']['enable']:
        wxwork_notification(notify['wxwork']['key'], content)

    if notify['dingtalk']['enable']:
        dingtalk_notification(notify['dingtalk']['access_token'], notify['dingtalk']['secret'], content)


