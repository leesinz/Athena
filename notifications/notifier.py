from config import cfg
from database.db_class import MySQLDatabase
from notifications.dingtalk import dingtalk_notification
from notifications.lark import lark_notification
from notifications.mail import email_notification
from notifications.wxwork import wxwork_notification


def send_realtime_notifications(content):
    notify = cfg['notify']
    if notify['wxwork']['enable']:
        wxwork_notification(notify['wxwork']['key'], content)
    if notify['dingtalk']['enable']:
        dingtalk_notification(notify['dingtalk']['access_token'], notify['dingtalk']['secret'], content)
    if notify['lark']['enable']:
        lark_notification(notify['lark']['access_token'], notify['lark']['secret'], content)


def send_daily_notifications(date):
    notify = cfg['notify']
    db = MySQLDatabase()
    query = f"SELECT * FROM vulnerabilities where date = %s"
    vulnerabilities = db.fetch_results(query, (date,))
    if vulnerabilities:
        email_notification(notify['email']['smtp_server'], notify['email']['smtp_port'], notify['email']['username'],
                           notify['email']['password'], notify['email']['from'], notify['email']['to'],
                           "Daily Vulnerability Report", vulnerabilities)
