"""CWE-501 Safe: constant/config source, not request."""
import configparser
from flask import session

def safe_constant():
    bar = "safe_value"
    session['userid'] = bar  # Safe — constant

def safe_configparser():
    conf = configparser.ConfigParser()
    conf.read('config.ini')
    bar = conf.get('section', 'key')
    session['token'] = bar  # Safe — config source

def safe_overwritten():
    param = request.cookies.get("id")
    bar = "default"  # overwritten with constant
    session['x'] = bar  # Safe
