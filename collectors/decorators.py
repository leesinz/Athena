# collectors/decorators.py
import requests
from functools import wraps
import time


def retry(max_retries=3, delay=2):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except requests.RequestException as e:
                    print(f"Request failed: {e}. Retrying {retries + 1}/{max_retries}...")
                    retries += 1
                    time.sleep(delay)
            print("Max retries reached. Exiting.")
            raise SystemExit("Max retries reached. Exiting.")

        return wrapper

    return decorator
