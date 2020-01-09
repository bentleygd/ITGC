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


def validate_email(email):
    """"Returns true if email passes validation."""
    if match(r'[a-zA-Z0-9_-]{1,32}\@[a-zA-Z0-9\.-]{1,96}', email):
        return True
    else:
        return False
