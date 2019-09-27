#!/usr/bin/python3
from subprocess import run, PIPE
from re import match, search


def getUsers(host):
    """Connect to host, get users, return list of users."""
    user_list = []
    no_shell = (r'/bin/false$|/sbin/nologin$|/bin/sync$|/sbin/halt$' +
                '|/sbin/shutdown$')
    file_contents = run(
        ['/usr/bin/ssh', host, 'cat', '/etc/passwd'],
        encoding='ascii', stdout=PIPE
        ).stdout.strip('\n').split('\n')
    for line in file_contents:
        if not match(no_shell, line.split(':')[6]):
            print(line)
            user_list.append(line.split(':')[0])
    return user_list


def getGroups(host):
    """Connect to host, get monitored groups, return groups."""
    groups = []
    monitored_groups = []
    m_groups = open('monitored_groups.list', mode='r', encoding='ascii')
    # Obtaining groups (and members) that will be monitored.
    host_groups = run(
        ['/usr/bin/ssh', host, 'cat', '/etc/group'],
         encoding='ascii', stdout=PIPE
         ).stdout.strip('\n').split('\n')
    for line in m_groups:
        groups.append(line.strip('\n'))
    print(groups)
    for group in groups:
        r_exp = r'^' + str(group) + r'.+\d{4,6}:'
        for host_group in host_groups:
            print('Searching for %s' % r_exp)
            if search(r_exp, host_group):
                monitored_groups.append(host_group)
    return monitored_groups
