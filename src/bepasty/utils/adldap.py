#!/usr/bin/python3

import sys
import os
import logging
import ldap
from .permissions import (READ,CREATE,DELETE,LIST,ADMIN)

class ADLDAPauth:
  def __init__(self, server, realm=None, base=None):
    self.server = server
    self.realm = realm
    self.base = base

  def authenticate(self, username, password):
    """ Try to bind with the given username and password
    """
    try:
      # allow server to use self-signed cert
      ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
      l = ldap.initialize(self.server)
      l.protocol_version = 3
      #l.start_tls_s()

      # don't go hunting down rabbit holes for referred objects
      l.set_option(ldap.OPT_REFERRALS, 0)
      l.set_option(ldap.OPT_DEREF, 0)

      if self.realm:
        DN = "{0}\\{1}".format(self.realm, username)
      elif self.base:
        DN = "cn={0},{1}".format(username, self.base)
      else:
        raise Exception("Must specify base or realm")

      res = l.simple_bind_s(DN, password)

      return True
    except Exception as e:
      logging.exception(e)
      return False

  def get_permissions(self):
    return ",".join((READ, CREATE, DELETE, LIST))

if __name__ == "__main__":

  server = "ldap://it.networkservice.associates"
  realm = "NETASSOC"
  base = "ou=associates,dc=it,dc=networkservice,dc=associates"
  username, secret = ('dharmsel', os.getenv('pwd'))

  auth = ADLDAP(server, realm=realm)
  print("realm:", auth.authenticate(username, secret))

  auth = ADLDAP(server, base=base)
  print("base:", auth.authenticate(username, secret))
