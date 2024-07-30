import time
import art
from processing.filter import gather_data, filter_high_risk_vuls
from database.init import create_db


def display_banner():
    banner = art.text2art("Athena", font='standard')
    print(banner)


def main():
    display_banner()
    create_db()
    while True:
        vulnerabilities = gather_data()
        filter_high_risk_vuls(vulnerabilities)
        time.sleep(600)


if __name__ == "__main__":
    main()
