"""Check private-server defaults and safe configuration updates without Docker."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from configure_server import configure


class ServerConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.path = self.directory / 'homeserver.yaml'
        self.path.write_text(yaml.safe_dump({
            'server_name': 'encptd.local',
            'signing_key_path': '/data/encptd.local.signing.key',
            'media_store_path': '/data/media_store',
        }))
        self.environment = {
            'CHAT_PUBLIC_URL': 'https://initial.example.com',
            'POSTGRES_PASSWORD': 'test-database-secret',
            'REGISTRATION_SHARED_SECRET': 'test-registration-secret',
            'MACAROON_SECRET_KEY': 'test-macaroon-secret',
            'FORM_SECRET': 'test-form-secret',
        }

    def test_no_open_signup_federation_or_plaintext_room_default(self):
        with patch.dict(os.environ, self.environment, clear=True):
            configure(self.directory)
        config = yaml.safe_load(self.path.read_text())
        self.assertIs(config['enable_registration'], False)
        self.assertIs(config['allow_guest_access'], False)
        self.assertEqual(config['federation_domain_whitelist'], [])
        self.assertEqual(config['encryption_enabled_by_default_for_room_type'], 'all')
        self.assertEqual(config['listeners'][0]['resources'][0]['names'], ['client'])

    def test_changing_tunnel_preserves_server_identity_and_persistent_paths(self):
        with patch.dict(os.environ, self.environment, clear=True):
            configure(self.directory)
            os.environ['CHAT_PUBLIC_URL'] = 'https://replacement.example.com'
            configure(self.directory)
        config = yaml.safe_load(self.path.read_text())
        self.assertEqual(config['server_name'], 'encptd.local')
        self.assertEqual(config['signing_key_path'], '/data/encptd.local.signing.key')
        self.assertEqual(config['media_store_path'], '/data/media_store')
        self.assertEqual(config['public_baseurl'], 'https://replacement.example.com/')

    def test_invalid_public_addresses_never_modify_existing_configuration(self):
        original = self.path.read_bytes()
        for url in ('http://example.com', 'https://user:pass@example.com',
                    'https://example.com/path', 'https://example.com?token=secret',
                    'https://example.com#fragment', 'https://'):
            with self.subTest(url=url), patch.dict(os.environ, self.environment, clear=True):
                os.environ['CHAT_PUBLIC_URL'] = url
                with self.assertRaises(ValueError):
                    configure(self.directory)
                self.assertEqual(self.path.read_bytes(), original)

    def test_existing_other_server_is_not_repurposed(self):
        self.path.write_text('server_name: other.example.com\n')
        original = self.path.read_bytes()
        with patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaises(ValueError):
                configure(self.directory)
        self.assertEqual(self.path.read_bytes(), original)

    def test_missing_credential_does_not_damage_existing_configuration(self):
        original = self.path.read_bytes()
        del self.environment['POSTGRES_PASSWORD']
        with patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaises(KeyError):
                configure(self.directory)
        self.assertEqual(self.path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
