#!/usr/bin/python3
from re import match


def validate_hn(hostname):
    """Returns true if string input matches hostname pattern."""
    if match(r'[a-zA-Z0-9\.-]{1,255}', hostname):
        return True
    else:
        return False


def validate_un(username):
    """Returns true if string input matches user name pattern."""
    if match(r'[a-zA-Z0-9\._-]{1,32}', username):
        return True
    else:
        return False
