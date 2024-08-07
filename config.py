import os

import yaml

config_dir = os.path.dirname(os.path.abspath(__file__))


def load_config(config_path=None):
    if config_path is None:
        config_path = os.path.join(config_dir, 'config.yaml')

    with open(config_path, 'r', encoding='UTF-8') as f:
        config = yaml.safe_load(f)
        update_by_env(config)
    return config


def update_by_env(config):
    traverse_dict(config)


def traverse_dict(config, obj=None, parent_key=None):
    if obj is None:
        obj = config
    if isinstance(obj, dict):
        for key, value in obj.items():
            if parent_key is not None:
                key_list = parent_key.copy()
            else:
                key_list = []
            key_list.append(key)
            if not isinstance(value, dict):
                update_config_key_from_env(config, key=key_list)
            else:
                traverse_dict(config=config, obj=value, parent_key=key_list)


def update_config_key_from_env(config, key):
    env_key = '_'.join(key).upper()
    value = os.getenv(env_key)
    update_config = config
    for k in key[:-1]:
        update_config = update_config[k]
    if value is not None:
        update_config[key[-1]] = value


cfg = load_config()
