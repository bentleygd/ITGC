#!/usr/bin/python3
from re import match


def ValidateHN(hostname):
    """Returns true if string input matches hostname pattern."""

    """The character lenght of 255 was chosen in order to be able to
       use the RegEx to check for compliance with RFC 1035 for DNS host
       names."""
    if match(r'[a-zA-Z0-9\.-]{1,255}', hostname):
        return True
    else:
        return False


def ValidateUN(username):
    """Returns true if string input matches user name pattern."""
    if match(r'[a-zA-Z0-9\._-]{1,32}', username):
        return True
    else:
        return False
