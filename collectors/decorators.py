# collectors/decorators.py
import requests
from functools import wraps
import time

from notifications.notifier import send_realtime_notifications


def retry(max_retries=3, delay=2):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(self, *args, **kwargs)
                except requests.RequestException as e:
                    print(f"Request failed: {e}. Retrying {retries + 1}/{max_retries}...")
                    retries += 1
                    time.sleep(delay)
            msg = f"fail to fetch {self.source_name} data due to network error"
            send_realtime_notifications(msg)
            return None

        return wrapper

    return decorator
