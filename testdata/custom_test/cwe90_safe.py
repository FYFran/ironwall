"""CWE-90 Safe: constant data in LDAP filter."""
import ldap3

def safe_constant():
    bar = "bob"
    base = "ou=users,ou=system"
    filter_str = f'(&(objectclass=person)(|(uid={bar})(street=The streetz)))'
    conn.search(base, filter_str, attributes=ldap3.ALL_ATTRIBUTES)

def safe_overwritten():
    param = request.cookies.get("id")
    bar = param
    bar = "alice"  # overwritten with constant
    filter_str = f'(uid={bar})'
    conn.search("base", filter_str)
