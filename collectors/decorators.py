# collectors/decorators.py
import requests
from functools import wraps
import time

from config import cfg
from notifications.notifier import send_realtime_notifications


def retry(max_retries=3, delay=2, timeout=10):
    if cfg['global']['max_retries']:
        max_retries = cfg['global']['max_retries']
    if cfg['global']['delay']:
        delay = cfg['global']['delay']
    if cfg['global']['timeout']:
        timeout = cfg['global']['timeout']

    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(self, *args, **kwargs, timeout=timeout)
                except (requests.RequestException, requests.Timeout) as e:
                    print(f"Request failed: {e}. Retrying {retries + 1}/{max_retries}...")
                    retries += 1
                    time.sleep(delay)
            if isinstance(self, str):
                msg = f"fail to fetch {self} data due to network error"
            else:
                msg = f"fail to fetch {self.source_name} data due to network error"
            send_realtime_notifications(msg)
            return None

        return wrapper

    return decorator
