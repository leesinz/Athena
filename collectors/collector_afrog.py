import datetime
import yaml
import requests
from .decorators import retry
from .base_collector import VulnerabilityCollector
from config import cfg

class AfrogCollector(VulnerabilityCollector):
    def __init__(self):
        afrog_url = "https://api.github.com/repos/zan8in/afrog/commits"
        afrog_headers = {
            "Authorization": f"token {cfg['github']['token']}",
        }
        super().__init__('Afrog', afrog_url)
        self.headers = afrog_headers

    @retry()
    def fetch_data(self):
        since = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat() + 'Z'
        response = requests.get(self.source_url, params={'since': since}, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @staticmethod
    @retry()
    def extract_info(file_path):
        url = f"https://raw.githubusercontent.com/zan8in/afrog/master/{file_path}"
        response = requests.get(url)
        body = response.text
        yaml_content = yaml.safe_load(body)
        name = yaml_content['info']['name']
        severity = yaml_content['info']['severity'].lower()
        description = yaml_content['info'].get('description', '')
        return name, severity, description

    def parse_data(self, raw_data):
        vulnerabilities_dict = {}
        for commit in raw_data:
            commit_url = commit['url']
            commit_response = requests.get(commit_url, headers=self.headers)
            if commit_response.status_code == 200:
                commit_data = commit_response.json()
                files = commit_data['files']
                for file in files:
                    dir_path = '/'.join(file['filename'].split('/')[:2])
                    if file['filename'].endswith('.yaml') and dir_path == 'pocs/afrog-pocs' and file['status'] == 'renamed':
                        name, severity, description = self.extract_info(file['filename'])
                        if file['filename'].split('/')[2] == 'CVE':
                            cve = file['filename'].split('/')[-1].split('.yaml')[0]
                        else:
                            cve = ''
                        vulnerability = {
                            'name': name,
                            'cve': cve,
                            'severity': severity,
                            'description': description,
                            'source': self.source_name,
                            'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'link': 'https://github.com/zan8in/afrog/blob/main/' + file['filename']
                        }
                        vulnerabilities_dict[vulnerability['name']] = vulnerability

        vulnerabilities = list(vulnerabilities_dict.values())
        return vulnerabilities

