import datetime
import requests
from config import cfg
from .decorators import retry
from .utils import extract_cve, process_cves
from .base_collector import VulnerabilityCollector


class VulhubCollector(VulnerabilityCollector):
    def __init__(self):
        vulhub_url = "https://api.github.com/repos/vulhub/vulhub/commits"
        vulhub_headers = {
            "Authorization": f"token {cfg['github']['token']}",
        }
        super().__init__('Vulhub', vulhub_url)
        self.headers = vulhub_headers

    @retry()
    def fetch_data(self, timeout):
        since = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat() + 'Z'
        response = requests.get(self.source_url, params={'since': since}, headers=self.headers, timeout=timeout)
        response.raise_for_status()
        return response.json()

    @retry()
    def extract_name(self, file_path, timeout):
        if cfg['github']['proxy'] == '':
            url = f"https://raw.githubusercontent.com/vulhub/vulhub/master/{file_path}/README.zh-cn.md"
        else:
            url = f"{cfg['github']['proxy']}https://raw.githubusercontent.com/vulhub/vulhub/master/{file_path}/README.zh-cn.md"
        response = requests.get(url, headers=self.headers, timeout=timeout)
        body = response.text
        title = body.split('\n', 1)[0].split('#')[1].strip()
        return title

    def parse_data(self, raw_data):
        vulnerabilities_dict = {}
        for commit in raw_data:
            commit_url = commit['url']
            commit_response = requests.get(commit_url, headers=self.headers)
            if commit_response.status_code == 200:
                commit_data = commit_response.json()
                files = commit_data['files']
                for file in files:
                    if file['filename'].split('/')[-1] == 'docker-compose.yml' and file['status'] == 'added':
                        full_path = '/'.join(file['filename'].split('/')[:-1])
                        name = self.extract_name(full_path)
                        cves = extract_cve(name)
                        _, description, severity = process_cves(cves)
                        vulnerability = {
                            'name': name,
                            'cve': cves,
                            'severity': severity,
                            'description': description,
                            'source': self.source_name,
                            'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'link': 'https://github.com/vulhub/vulhub/tree/master/' + '/'.join(
                                file['filename'].split('/')[:-1])
                        }
                        vulnerabilities_dict[vulnerability['name']] = vulnerability

        vulnerabilities = list(vulnerabilities_dict.values())
        return vulnerabilities
