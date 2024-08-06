import datetime
import requests
from config import cfg
from .decorators import retry
from .utils import extract_cve, process_cves
from .base_collector import VulnerabilityCollector


class POCCollector(VulnerabilityCollector):
    def __init__(self):
        poc_url = "https://api.github.com/repos/wy876/POC/commits"
        poc_headers = {
            "Authorization": f"token {cfg['github']['token']}",
        }
        super().__init__('POC', poc_url)
        self.headers = poc_headers

    @retry()
    def fetch_data(self):
        since = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat() + 'Z'
        response = requests.get(self.source_url, params={'since': since}, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def parse_data(self, raw_data):
        vulnerabilities_dict = {}
        for commit in raw_data:
            commit_url = commit['url']
            commit_response = requests.get(commit_url, headers=self.headers)
            if commit_response.status_code == 200:
                commit_data = commit_response.json()
                files = commit_data['files']
                for file in files:
                    if file['filename'].endswith('.md') and file['status'] == 'added':
                        name = file['filename'].split('.md')[0]
                        cves = extract_cve(name)
                        _, description, severity = process_cves(cves)
                        vulnerability = {
                            'name': name,
                            'cve': cves,
                            'severity': severity,
                            'description': description,
                            'source': self.source_name,
                            'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'link': 'https://github.com/wy876/POC/blob/main/' + file['filename']
                        }
                        vulnerabilities_dict[vulnerability['name']] = vulnerability

        vulnerabilities = list(vulnerabilities_dict.values())
        return vulnerabilities
