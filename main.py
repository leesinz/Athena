import datetime
import threading
import time
import art
from notifications.notifier import send_daily_notifications
from processing.filter import gather_data, filter_high_risk_vuls
from database.init import create_db
from flaskr.app import app


def display_banner():
    banner = art.text2art("Athena", font='standard')
    print(banner)


def daily_task():
    yesterday = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    send_daily_notifications(yesterday)


def run_flask_app():
    app.run(debug=False)


def main():
    display_banner()
    create_db()

    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.start()

    last_sent_date = None
    while True:
        current_time = datetime.datetime.now()
        current_date = current_time.date()

        if current_time.hour == 6 and last_sent_date != current_date:
            daily_task()
            last_sent_date = current_date

        vulnerabilities = gather_data()
        filter_high_risk_vuls(vulnerabilities)
        time.sleep(600)


if __name__ == "__main__":
    main()
