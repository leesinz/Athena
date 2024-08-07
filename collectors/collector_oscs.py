import datetime
from dateutil import parser
import requests
from .decorators import retry
from .base_collector import VulnerabilityCollector


class OSCSCollector(VulnerabilityCollector):
    def __init__(self):
        oscs_url = "https://www.oscs1024.com/oscs/v1/intelligence/list"
        oscs_data = {
            "page": 1,
            "per_page": 10
        }
        super().__init__('OSCS', oscs_url)
        self.data = oscs_data

    @retry()
    def fetch_data(self, timeout):
        response = requests.post(self.source_url, json=self.data, timeout=timeout)
        response.raise_for_status()
        return response.json()

    @staticmethod
    @retry()
    def extract_info(mps, timeout):
        url = "https://www.oscs1024.com/oscs/v1/vdb/info"
        headers = {
            "Host": "www.oscs1024.com",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36"
        }
        data = {
            "vuln_no": mps
        }
        response = requests.post(url, headers=headers, json=data, timeout=timeout)
        response.raise_for_status()
        data = response.json()['data'][0]
        cve = data['cve_id']
        description = data['description']
        severity = data['level'].lower()
        return cve, description, severity

    def parse_data(self, raw_data):
        today = datetime.date.today().strftime("%Y-%m-%d")
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        vulnerabilities = []
        items = raw_data['data']['data']
        for item in items:
            public_time = item['public_time'].split('T')[0]
            if public_time != today and public_time != yesterday:
                continue
            date = parser.parse(item['public_time']).strftime("%Y-%m-%d %H:%M:%S")
            name = item['title']
            link = item['url']
            mps = item['mps']
            infos = self.extract_info(mps)
            vulnerability = {
                "name": name,
                'cve': infos[0],
                'severity': infos[2],
                'description': infos[1],
                "source": self.source_name,
                "date": date,
                "link": link,
            }
            vulnerabilities.append(vulnerability)
        return vulnerabilities
