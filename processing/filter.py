import html
from tqdm import tqdm
from config import cfg
from database.db_class import MySQLDatabase
from collectors.manager import VulnerabilityManager
from notifications.notifier import send_notifications


def gather_data():
    manager = VulnerabilityManager()
    selected_collectors = cfg.get('collectors', [])
    all_vulnerabilities = []

    with tqdm(total=len(manager.collector_classes), desc="Collecting vulnerabilities") as pbar:
        for collector_name, collector_class in manager.collector_classes.items():
            if collector_name in selected_collectors or not selected_collectors:
                tqdm.write(f"Collecting data from {collector_name}")
                collector_instance = collector_class()
                vulnerabilities = collector_instance.collect_vulnerabilities()
                all_vulnerabilities.extend(vulnerabilities)
            pbar.update(1)

    return all_vulnerabilities


def filter_high_risk_vuls(vulnerabilities):
    print("Filtering high risk vulnerabilities")
    high_risk_num = 0
    db = MySQLDatabase()
    for vulnerability in vulnerabilities:
        vulnerability = {key: html.unescape(value) for key, value in vulnerability.items()}
        if vulnerability['source'] == 'QAX':
            already_exists = db.check_vulnerability_exists("name", vulnerability['name'])
        else:
            already_exists = db.check_vulnerability_exists("link", vulnerability['link'])
        if already_exists:
            continue

        db.insert_vulnerability(vulnerability)

        high_risk_list = ['high', 'critical']
        if vulnerability['severity'] in high_risk_list or vulnerability['source'] == 'QAX':
            high_risk_num += 1
            content = ""
            for key, value in vulnerability.items():
                if value:
                    content += f"{key}: {value}\n"
            content = content.rstrip("\n")
            send_notifications("vulnerability notifier", "", content)
    print(f"High risk vulnerabilities found: {high_risk_num}\n")

