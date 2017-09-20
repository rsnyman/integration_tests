from __future__ import unicode_literals
import os
try:
    # Python 3
    from configparser import ConfigParser
except ImportError:
    # Python 2
    from ConfigParser import SafeConfigParser as ConfigParser

from hvac import Client

VAULT_URL = 'http://10.8.198.21:8200'
SECRET_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '.keyfile'))


class Credentials(object):
    """A credentials keystore backed in Vault"""

    def __init__(self, vault_url, auth_file=None, mount_point='secret', base_path=''):
        """Create a client"""
        self._cache = {}
        self._mount_point = mount_point
        self._base_path = base_path
        self._client = Client(url=vault_url)
        if auth_file:
            self._auth_file = auth_file
        else:
            self._auth_file = SECRET_FILE
        self._config = ConfigParser()
        self._config.read(self._auth_file)
        if self._config.has_section('auth'):
            if self._config.has_option('auth', 'token'):
                self._client.token = self._config.get('auth', 'token')
                self._client.is_authenticated()
            elif (self._config.has_option('auth', 'ldap_username') and
                    self._config.has_option('auth', 'ldap_password')):
                self._client.auth_ldap(self._config.get('auth', 'ldap_username'),
                                       self._config.get('auth', 'ldap_password'))

    def make_path(self, key=None):
        """Construct a key path"""
        segments = [self._mount_point]
        if self._base_path:
            segments.append(self._base_path)
        if key:
            segments.append(key)
        return '/'.join(segments)

    def store(self, key, **kwargs):
        """Store a username and password in Vault"""
        self._client.write(self.make_path(key), **kwargs)

    def retrieve(self, key):
        """Get a value from Vault"""
        if key in self._cache:
            return self._cache[key]
        value = self._client.read(self.make_path(key))['data']
        self._cache[key] = value
        return value

    def __getitem__(self, key):
        """Implement dict-like access"""
        return self.retrieve(key)

    def iterkeys(self):
        """Return a list of keys"""
        result = self._client.list(self.make_path())
        for key in result['data']['keys']:
            yield key


credentials = Credentials(VAULT_URL, base_path='cfme-qe')
