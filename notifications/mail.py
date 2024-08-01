import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader, select_autoescape


def email_notification(server, port, username, password, from_user, to_user, subject, vulnerabilities):
    file_loader = FileSystemLoader('.')
    env = Environment(loader=file_loader, autoescape=select_autoescape(['html', 'xml']))
    template = env.get_template('notifications/email_template.html')
    html_content = template.render(vulnerabilities=vulnerabilities)

    try:
        msg = MIMEMultipart()
        msg['From'] = from_user
        msg['To'] = ', '.join(to_user)
        msg['Subject'] = subject

        msg.attach(MIMEText(html_content, 'html'))

        with smtplib.SMTP(server, port) as server:
            server.starttls()
            server.login(username, password)
            server.sendmail(msg['From'], msg['To'], msg.as_string())
            print('Email sent successfully!')
    except Exception as e:
        print(f'Failed to send email. Error: {str(e)}')

