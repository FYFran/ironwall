"""CWE-90 Vulnerable: request data flows into LDAP filter."""
from flask import request
import ldap3

def vulnerable_ldap_search():
    uid = request.cookies.get("user_id")
    bar = uid
    base = "ou=users,ou=system"
    filter_str = f'(&(objectclass=person)(|(uid={bar})(street=The streetz)))'
    conn.search(base, filter_str, attributes=ldap3.ALL_ATTRIBUTES)

def vulnerable_via_args():
    name = request.args.get("name")
    base = "dc=example,dc=com"
    filter_str = f'(cn={name})'
    conn.search(base, filter_str, attributes=['cn', 'mail'])
