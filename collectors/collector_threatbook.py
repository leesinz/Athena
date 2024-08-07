import datetime
import requests
from .decorators import retry
from .base_collector import VulnerabilityCollector


class ThreatBookCollector(VulnerabilityCollector):
    def __init__(self):
        threatbook_url = "https://x.threatbook.com/v5/node/vul_module/homePage"
        threatbook_headers = {
            "Host": "x.threatbook.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36",
        }
        super().__init__('ThreatBook', threatbook_url)
        self.headers = threatbook_headers

    @retry()
    def fetch_data(self, timeout):
        response = requests.get(self.source_url,headers=self.headers, timeout=timeout)
        response.raise_for_status()
        return response.json()

    def parse_data(self, raw_data):
        today = datetime.date.today().strftime("%Y-%m-%d")
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        vulnerabilities = []
        items = raw_data['data']['highrisk']
        for item in items:
            vuln_update_time = item['vuln_update_time']
            if vuln_update_time != today and vuln_update_time != yesterday:
                continue
            id = item['id']
            name = item['vuln_name_zh']
            link = "https://x.threatbook.com/v5/vul/" + id
            vulnerability = {
                "name": name,
                "cve": "",
                "severity": "high",
                "description": "",
                "source": self.source_name,
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "link": link,
            }
            vulnerabilities.append(vulnerability)
        return vulnerabilities
