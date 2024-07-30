import re
from bs4 import BeautifulSoup
import requests


def extract_cve(name):
    cve_pattern = r'CVE-\d{4}-\d{4,10}'
    cves = re.findall(cve_pattern, name.upper())
    return ','.join(cves)


def extract_score(soup, selector):
    element = soup.select_one(selector)
    return element.text.split()[0] if element else "0.0"


def get_cve_info(cve):
    url = "https://nvd.nist.gov/vuln/detail/" + cve
    try:
        res = requests.get(url)
        res.raise_for_status()
    except requests.RequestException as e:
        print(f"Error establishing connection: {e}")
        return False, "", "", "", ""

    soup = BeautifulSoup(res.content, 'html.parser')
    exists = bool(soup.select_one("#vulnDetailPanel"))
    cvss3 = extract_score(soup, "[data-testid=vuln-cvss3-panel-score]")
    cna = extract_score(soup, "[data-testid=vuln-cvss3-cna-panel-score]")
    cvss2 = extract_score(soup, "span.severityDetail a#Cvss2CalculatorAnchor")
    desc = soup.select_one("[data-testid=vuln-description]").text.strip() if soup.select_one(
        "[data-testid=vuln-description]") else ""

    return exists, desc, cvss2, cvss3, cna


def get_severity(score):
    severity_ranges = {
        (0.0, 4.0): 'low',
        (4.0, 7.0): 'medium',
        (7.0, 9.0): 'high',
        (9.0, 10.0): 'critical'
    }
    for (lower, upper), severity in severity_ranges.items():
        if lower <= score < upper:
            return severity
    if score == 10.0:
        return 'critical'
    return ''


def process_cves(cve_string):
    if not cve_string:
        return False, "", ""

    cve_list = cve_string.split(',')
    overall_exists = True
    all_descs = []
    max_score = 0.0

    for cve in cve_list:
        exists, desc, cvss2, cvss3, cna = get_cve_info(cve)
        overall_exists = overall_exists and exists
        all_descs.append(desc)

        scores = [float(score) for score in (cvss2, cvss3, cna) if score]
        if scores:
            max_score = max(max_score, *scores)

    combined_desc = '\n'.join(all_descs)
    severity = get_severity(max_score)

    return overall_exists, combined_desc, severity
