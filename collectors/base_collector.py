from abc import ABC, abstractmethod


class VulnerabilityCollector(ABC):
    def __init__(self, source_name, source_url):
        self.source_name = source_name
        self.source_url = source_url

    @abstractmethod
    def fetch_data(self):
        pass

    @abstractmethod
    def parse_data(self, raw_data):
        pass

    def collect_vulnerabilities(self):
        raw_data = self.fetch_data()
        if raw_data:
            return self.parse_data(raw_data)
        else:
            return []
