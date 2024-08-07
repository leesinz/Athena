from config import cfg
from database.db_class import MySQLDatabase
from notifications.mail import email_notification
from notifications.dingtalk import dingtalk_notification
from notifications.wxwork import wxwork_notification
from notifications.feishu import feishu_notification


def send_realtime_notifications(content):
    notify = cfg['notify']
    if notify['wxwork']['enable']:
        wxwork_notification(notify['wxwork']['key'], content)
    if notify['dingtalk']['enable']:
        dingtalk_notification(notify['dingtalk']['access_token'], notify['dingtalk']['secret'], content)
    if notify['feishu']['enable']:
        feishu_notification(notify['feishu']['webhook'], notify['feishu']['secret'], content)


def send_daily_notifications(date):
    notify = cfg['notify']
    db = MySQLDatabase()
    query = f"SELECT * FROM vulnerabilities where date = %s"
    vulnerabilities = db.fetch_results(query, (date,))
    if vulnerabilities:
        email_notification(notify['email']['smtp_server'], notify['email']['smtp_port'], notify['email']['username'],
                           notify['email']['password'], notify['email']['from'], notify['email']['to'],
                           "Daily Vulnerability Report", vulnerabilities)
