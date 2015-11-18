import os
import sys

import ldap
import ldap.resiter
from pymongo import MongoClient

from iam.hash import hash_md5

USER_COLLECTION = 'users'
USER_UPDATE_COLLECTION = 'users_update'
HASH_SALT = os.environ.get('HASH_SALT')
MONGO_SERVER = os.environ.get('MONGO_SERVER', 'localhost')
MONGO_PORT = os.environ.get('MONGO_PORT', 27017)
MONGO_DB = os.environ.get('MONGO_DB', 'iam')
LDAP_URI = os.environ.get('LDAP_URI', 'ldaps://localhost:636')
LDAP_BIND_USER = os.environ.get('LDAP_BIND_USER')
LDAP_BIND_PASSWORD = os.environ.get('LDAP_BIND_PASSWORD')
LDAP_SEARCH_BASE = os.environ.get('LDAP_SEARCH_BASE')
LDAP_SEARCH_FILTER = os.environ.get('LDAP_SEARCH_FILTER')
LDAP_SEARCH_ATTRLIST = os.environ.get('LDAP_SEARCH_ATTRLIST')


class MyLDAPObject(ldap.ldapobject.LDAPObject, ldap.resiter.ResultProcessor):
    pass

print("LDAP Server: {}@{}/{}/{}".format(LDAP_BIND_USER, LDAP_URI, LDAP_SEARCH_BASE, LDAP_SEARCH_FILTER))
print("LDAP Attributes: {}".format(LDAP_SEARCH_ATTRLIST))
print("Mongo: {}:{}/{}".format(MONGO_SERVER, MONGO_PORT, MONGO_DB))

# initialize mongo client
client = MongoClient(MONGO_SERVER, int(MONGO_PORT))
db = client[MONGO_DB]

l = MyLDAPObject(LDAP_URI)
l.simple_bind_s(LDAP_BIND_USER, LDAP_BIND_PASSWORD)
# Asynchronous search method
msg_id = l.search(LDAP_SEARCH_BASE, ldap.SCOPE_SUBTREE, LDAP_SEARCH_FILTER, LDAP_SEARCH_ATTRLIST.split(','))

users = []
for res_type, res_data, res_msgid, res_controls in l.allresults(msg_id):
    for dn, entry in res_data:
        # process dn and entry
        # print dn, entry
        if len(entry['ubcEduCwlPUID']) != 1 or len(entry.get('ubcEduStudentNumber', [])) > 1 \
                or len(entry.get('employeeNumber', [])) > 1 or len(entry.get('mail', [])) > 1 or len(entry.get('cn', [])) > 1:
            print dn, entry
            print '************************^^^^^^^^^^*************'
        entry['edx_id'] = hash_md5(entry['ubcEduCwlPUID'][0], HASH_SALT)
        entry['ubcEduCwlPUID'] = entry['ubcEduCwlPUID'][0]
        entry['uid'] = entry['uid'][0]
        if 'cn' in entry:
            entry['cn'] = entry['cn'][0]
        if 'displayName' in entry:
            entry['displayName'] = entry['displayName'][0]
        if 'employeeNumber' in entry:
            entry['employeeNumber'] = entry['employeeNumber'][0]
        if 'ubcEduStudentNumber' in entry:
            entry['ubcEduStudentNumber'] = entry['ubcEduStudentNumber'][0]
        if 'mail' in entry:
            entry['mail'] = entry['mail'][0]

        users.append(entry)
        if len(users) >= 5000:
            db[USER_UPDATE_COLLECTION].insert_many(users)
            users = []
            sys.stdout.write(".")
            sys.stdout.flush()

db[USER_UPDATE_COLLECTION].insert_many(users)
sys.stdout.write(".")
sys.stdout.flush()

l.unbind_s()

db[USER_UPDATE_COLLECTION].rename(USER_COLLECTION, dropTarget=True)

print 'Done'
