import datetime
import requests
from .decorators import retry
from .base_collector import VulnerabilityCollector


class QAXCollector(VulnerabilityCollector):
    def __init__(self):
        qax_url = "https://ti.qianxin.com/alpha-api/v2/vuln/article-notice"
        qax_headers = {
            "Host": "ti.qianxin.com",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36",
            "Accept-Encoding": "gzip, deflate, br"
        }

        qax_data = {
            "page_no": 1,
            "page_size": 10,
            "category": "风险通告"
        }
        super().__init__('QAX', qax_url)
        self.headers = qax_headers
        self.data = qax_data

    @retry()
    def fetch_data(self):
        response = requests.post(self.source_url,headers=self.headers,json=self.data)
        response.raise_for_status()
        return response.json()

    def parse_data(self, raw_data):
        today = datetime.date.today().strftime("%Y-%m-%d")
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        vulnerabilities = []
        items = raw_data['data']['data']
        for item in items:
            update_time = item['update_time'].split(' ')[0]
            if update_time != today and update_time != yesterday:
                continue
            name = item['title']

            vulnerability = {
                "name": name,
                "cve": "",
                "severity": "high",
                "description": "",
                "source": self.source_name,
                "date": item['update_time'],
                "link": "https://ti.qianxin.com/alpha-api/v2/vuln/article-notice",
            }
            vulnerabilities.append(vulnerability)
        return vulnerabilities
