"""Apply the private-server defaults inside the official Synapse container."""

import os
from pathlib import Path
from urllib.parse import urlsplit

import yaml


def configure(data_directory=Path('/data')):
    public_url = os.environ['CHAT_PUBLIC_URL'].rstrip('/')
    parsed = urlsplit(public_url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path):
        raise ValueError('CHAT_PUBLIC_URL must be an HTTPS origin')
    path = data_directory / 'homeserver.yaml'
    config = yaml.safe_load(path.read_text())
    if config.get('server_name') != 'encptd.local':
        raise ValueError('This installation uses the fixed server identity encptd.local')
    config.update({
        'public_baseurl': public_url + '/',
        'report_stats': False,
        'enable_registration': False,
        'allow_guest_access': False,
        'registration_shared_secret': os.environ['REGISTRATION_SHARED_SECRET'],
        'macaroon_secret_key': os.environ['MACAROON_SECRET_KEY'],
        'form_secret': os.environ['FORM_SECRET'],
        'federation_domain_whitelist': [],
        'trusted_key_servers': [],
        'suppress_key_server_warning': True,
        'url_preview_enabled': False,
        'enable_metrics': False,
        'encryption_enabled_by_default_for_room_type': 'all',
        'max_upload_size': '25M',
        'presence': {'enabled': False},
        'database': {
            'name': 'psycopg2',
            'args': {
                'user': 'synapse', 'password': os.environ['POSTGRES_PASSWORD'],
                'database': 'synapse', 'host': 'db', 'port': 5432,
                'cp_min': 2, 'cp_max': 5,
            },
        },
        'listeners': [{
            'port': 8008, 'type': 'http', 'tls': False,
            'bind_addresses': ['0.0.0.0'], 'x_forwarded': True,
            'resources': [{'names': ['client'], 'compress': False}],
        }],
    })
    temporary = path.with_suffix('.tmp')
    temporary.write_text(yaml.safe_dump(config, sort_keys=False))
    temporary.replace(path)
    print('Applied ENCPTD server configuration. No credentials printed.')


if __name__ == '__main__':
    configure()
