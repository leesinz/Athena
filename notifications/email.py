import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def email_notification(server, port, username, password, from_user, to_user, subject, message):
    msg = MIMEMultipart()
    msg['From'] = from_user
    msg['To'] = ', '.join(to_user)
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))

    try:
        with smtplib.SMTP(server, port) as server:
            server.login(username, password)
            server.sendmail(from_user, to_user, msg.as_string())
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")
