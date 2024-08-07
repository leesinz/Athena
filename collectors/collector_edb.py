import datetime
import requests
import re
from .decorators import retry
from .utils import process_cves
from .base_collector import VulnerabilityCollector


class ExploitDBCollector(VulnerabilityCollector):
    def __init__(self):
        edb_base_url = "https://www.exploit-db.com/?columns%5B9%5D%5Bname%5D=id&order%5B0%5D%5Bcolumn%5D=9&start={}&length={}"
        start_value = 0
        length_value = 30
        edb_url = edb_base_url.format(start_value, length_value)
        edb_headers = {
            "Host": "www.exploit-db.com",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36"
        }
        super().__init__('Exploit-DB', edb_url)
        self.headers = edb_headers

    @retry()
    def fetch_data(self, timeout):
        response = requests.get(self.source_url, headers=self.headers, timeout=timeout)
        response.raise_for_status()
        return response.json()

    def parse_data(self, raw_data):
        today = datetime.date.today().strftime("%Y-%m-%d")
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        vulnerabilities = []
        if raw_data and 'data' in raw_data:
            for item in raw_data['data']:
                date_published = item['date_published']
                if date_published != today and date_published != yesterday:
                    continue
                code_list = item['code']
                cves = []
                pattern = r'\d{4}-\d{4,10}'
                for code in code_list:
                    if code['code_type'] == 'cve':
                        match = re.search(pattern, code['code'])
                        if match:
                            cve = 'CVE-' + match.group()
                            cves.append(cve)
                cves_string = ','.join(cves)
                _, desc, severity = process_cves(cves_string)
                desc_list = item['description']
                vulnerability = {
                    'name': desc_list[1],
                    'cve': cves_string,
                    'severity': severity,
                    'description': desc,
                    'source': self.source_name,
                    'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'link': 'https://www.exploit-db.com/exploits/' + desc_list[0]
                }
                vulnerabilities.append(vulnerability)
        return vulnerabilities
