import yaml
import os

config_dir = os.path.dirname(os.path.abspath(__file__))


def load_config(config_path=None):
    if config_path is None:
        config_path = os.path.join(config_dir, 'config.yaml')

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config


cfg = load_config()
