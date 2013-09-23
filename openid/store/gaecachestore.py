"""
An OpenIDStore implementation that uses the Google App Engine
memcache servers as its backing store.

Stores associations, nonces, and authentication tokens.

OpenIDStore is an interface from JanRain's OpenID python library:
    http://openidenabled.com/python-openid/

For more, see openid/store/interface.py in that library.
"""

import datetime
import pickle

from openid.store.interface import OpenIDStore
from google.appengine.api import memcache

_GAE_MEMCACHE_NAMESPACE = 'openid_store'

class ServerAssocs(object):
    def __init__(self):
        self.assocs = {}

    def set(self, assoc):
        self.assocs[assoc.handle] = assoc

    def get(self, handle):
        return self.assocs.get(handle)

    def remove(self, handle):
        try:
            del self.assocs[handle]
        except KeyError:
            return False
        else:
            return True

    def best(self):
        """Returns association with the oldest issued date.

        or None if there are no associations.
        """
        best = None
        for assoc in self.assocs.values():
            if best is None or best.issued < assoc.issued:
                best = assoc
        return best

    def empty(self):
        return len(self.assocs) == 0

class MemcacheStore(OpenIDStore):
    def getAssocFromStore(self, server_url):
        key = 'association_' + server_url
        assoc = memcache.get(key, namespace=_GAE_MEMCACHE_NAMESPACE)
        if assoc:
            assoc = pickle.loads(assoc)
        else:
            assoc = ServerAssocs()
        return assoc

    def storeAssociation(self, server_url, association):
        assoc = self.getAssocFromStore(server_url)
        assoc.set(association)
        key = 'association_' + server_url
        memcache.set(key, pickle.dumps(assoc), namespace=_GAE_MEMCACHE_NAMESPACE)

    def getAssociation(self, server_url, handle=None):
        assoc = self.getAssocFromStore(server_url)
        if handle:
            return assoc.get(handle)
        else:
            return assoc.best()

    def removeAssociation(self, server_url, handle):
        assoc = self.getAssocFromStore(server_url)
        assoc.remove(handle)
        key = 'association_' + server_url
        if assoc.empty():
            memcache.delete(key)
        else:
            memcache.set(key, pickle.dumps(assoc), namespace=_GAE_MEMCACHE_NAMESPACE)

    def storeNonce(self, nonce):
        key = 'nonce_' + nonce
        memcache.set(key, datetime.datetime.now(), namespace=_GAE_MEMCACHE_NAMESPACE)

    def useNonce(self, nonce):
        key = 'nonce_' + nonce
        expiry = memcache.get(key, namespace=_GAE_MEMCACHE_NAMESPACE)
        if expiry:
            memcache.delete(key, namespace=_GAE_MEMCACHE_NAMESPACE)
        if expiry:
            return expiry >= datetime.datetime.now() - datetime.timedelta(hours=6)
        else:
            return False

