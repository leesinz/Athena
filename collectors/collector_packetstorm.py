import datetime
import requests
from .decorators import retry
from bs4 import BeautifulSoup
from .utils import process_cves
from .base_collector import VulnerabilityCollector


class PacketStormCollector(VulnerabilityCollector):
    def __init__(self):
        packetstorm_url = "https://packetstormsecurity.com/files/tags/exploit"
        super().__init__('PacketStorm', packetstorm_url)

    @retry()
    def fetch_data(self):
        response = requests.get(self.source_url)
        response.raise_for_status()
        return response.content

    def parse_data(self, raw_data):
        vulnerabilities = []
        soup = BeautifulSoup(raw_data, 'html.parser')
        for item in soup.find_all("dl", id=True):
            date_tag = item.find("dd", class_="datetime")
            posted_date = date_tag.find("a")['href'].strip().split('/')[-2]
            if posted_date != datetime.date.today().strftime("%Y-%m-%d"):
                continue
            name = item.find("dt").find("a").text.strip()
            cve_section = item.find("dd", class_="cve")
            cves = []
            if cve_section:
                cve_links = cve_section.find_all("a")
                cves = [cve.text for cve in cve_links]
            cve_str = ",".join(cves)
            _, desc, severity = process_cves(cve_str)
            poc_link = item.find("dd", class_="act-links").find_all("a", href=True)
            view_link = ""
            for link in poc_link:
                if "View" in link.text:
                    view_link = "https://packetstormsecurity.com" + link['href']
                    break

            vulnerability = {
                "name": name,
                "cve": cve_str,
                "severity": severity,
                "description": desc,
                "source": self.source_name,
                "date": posted_date,
                "link": view_link
            }
            vulnerabilities.append(vulnerability)
        return vulnerabilities
