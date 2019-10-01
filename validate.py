#!/usr/bin/python3
from re import match


def ValidateHN(hostname):
    """Returns true if string input matches hostname pattern."""
    host = hostname.encode('ascii')
    if match(r'[a-zA-Z0-9\.-]{1,96}', host):
        return True
    else:
        return False


def ValidateUN(username):
    """Returns true if string input matches user name pattern."""
    user = username.encode('ascii')
    if match(r'[a-zA-Z0-9\._-]{1,32}', user):
        return True
    else:
        return False
