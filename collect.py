import argparse
import os
import sys

import ldap.resiter
import time
from pymongo import MongoClient

from iam.hash import hash_md5

USER_COLLECTION = 'users'
USER_UPDATE_COLLECTION = 'users_update'
HASH_SALT = os.environ.get('HASH_SALT')
MONGO_SERVER = os.environ.get('MONGO_SERVER', 'localhost:27017')
MONGO_DB = os.environ.get('MONGO_DB', 'iam')
MONGO_USER = os.environ.get('MONGO_USER', None)
MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD', None)
LDAP_URI = os.environ.get('LDAP_URI', 'ldaps://localhost:636')
LDAP_BIND_USER = os.environ.get('LDAP_BIND_USER')
LDAP_BIND_PASSWORD = os.environ.get('LDAP_BIND_PASSWORD')
LDAP_SEARCH_BASE = os.environ.get('LDAP_SEARCH_BASE')
LDAP_SEARCH_FILTER = os.environ.get('LDAP_SEARCH_FILTER', 'objectClass=*')
LDAP_SEARCH_ATTRLIST = os.environ.get('LDAP_SEARCH_ATTRLIST')
DEBUG = os.environ.get('DEBUG', False) in ['true', 'True', '1', 'y', 'yes']
SLEEP = int(os.environ.get('SLEEP', 10))


parser = argparse.ArgumentParser()
parser.add_argument('-s', '--salt', help='The salt for hash calculation', default=HASH_SALT)
parser.add_argument('-l', '--ldap', help='LDAP URI', default=LDAP_URI)
parser.add_argument('-u', '--bind', help='LDAP bind user', default=LDAP_BIND_USER)
parser.add_argument('-p', '--password', help='LDAP bind password', default=LDAP_BIND_PASSWORD)
parser.add_argument('-b', '--base', help='LDAP search base', default=LDAP_SEARCH_BASE)
parser.add_argument('-f', '--filter', help='LDAP search filter', default=LDAP_SEARCH_FILTER)
parser.add_argument('-a', '--attr', help='LDAP search attribute list, comma separated', default=LDAP_SEARCH_ATTRLIST)
parser.add_argument('-d', '--debug', help='Debug', default=DEBUG, action='store_true')
parser.add_argument('-e', '--sleep', help='Sleep between each bulk insert', type=int, default=SLEEP)
parser.add_argument('-m', '--host', help='Mongo host', default=MONGO_SERVER)
parser.add_argument('-n', '--db', help='Mongo database', default=MONGO_DB)
parser.add_argument('-w', '--mongouser', help='Mongo database user', default=MONGO_USER)
parser.add_argument('-x', '--mongopass', help='Mongo database password', default=MONGO_PASSWORD)


args = parser.parse_args()


class MyLDAPObject(ldap.ldapobject.LDAPObject, ldap.resiter.ResultProcessor):
    pass

if args.debug:
    print("LDAP Server: {}@{}/{}/{}".format(args.bind, args.ldap, args.base, args.filter))
    print("LDAP Pass: {}".format(args.password))
    print("LDAP Attributes: {}".format(args.attr))
    print("Mongo: {}/{}".format(args.host, args.db))
    print("Hash Salt: {}".format(args.salt))

# initialize mongo client
client = MongoClient(args.host)
# wait for pymongo to discover replicaset
time.sleep(0.5)

db = client[args.db]

# authenticate if user is provided
if args.mongouser:
    db.authenticate(args.mongouser, args.mongopass, source='admin')

print("Database connected.")

db.drop_collection(USER_UPDATE_COLLECTION)

l = MyLDAPObject(args.ldap)
# l.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
l.simple_bind_s(args.bind, args.password)
# Asynchronous search method
msg_id = l.search(args.base, ldap.SCOPE_SUBTREE, args.filter, args.attr.split(','))

users = []
for res_type, res_data, res_msgid, res_controls in l.allresults(msg_id):
    for dn, entry in res_data:
        # process dn and entry
        if "uid" not in entry:
            continue
        # print dn, entry
        if len(entry['ubcEduCwlPUID']) != 1 or len(entry.get('ubcEduStudentNumber', [])) > 1 \
                or len(entry.get('employeeNumber', [])) > 1 or len(entry.get('mail', [])) > 1 or len(entry.get('cn', [])) > 1:
            print dn, entry
            print '************************^^^^^^^^^^*************'
        if args.debug:
            print("Hash base string for {} is {}.".format(entry['ubcEduCwlPUID'][0], entry['ubcEduCwlPUID'][0] + args.salt))
        entry['edx_id'] = hash_md5(entry['ubcEduCwlPUID'][0], args.salt)
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
            time.sleep(args.sleep)

db[USER_UPDATE_COLLECTION].insert_many(users)
sys.stdout.write(".")
sys.stdout.flush()

l.unbind_s()

db[USER_UPDATE_COLLECTION].rename(USER_COLLECTION, dropTarget=True)

print 'Done'
