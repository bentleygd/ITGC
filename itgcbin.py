#!/usr/bin/python3
from subprocess import run, PIPE
from re import match, search
from socket import gethostbyname, socket, AF_INET, SOCK_STREAM
from socket import gaierror, timeout


def getUsers(host):
    """Connect to host, get users, return list of users."""
    user_list = []
    no_shell = (r'/bin/false$|/sbin/nologin$|/bin/sync$|/sbin/halt$' +
                '|/sbin/shutdown$')
    # Connect to remote system, get a list of all user accounts that
    # have an interactive shell.
    file_contents = run(
        ['/usr/bin/ssh', host, 'cat', '/etc/passwd'],
        encoding='ascii', stdout=PIPE
        ).stdout.strip('\n').split('\n')
    for line in file_contents:
        if not match(no_shell, line.split(':')[6]):
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
    for group in groups:
        r_exp = r'^' + str(group) + r'.+\d{4,6}:'
        for host_group in host_groups:
            if search(r_exp, host_group):
                monitored_groups.append(host_group)
    return monitored_groups


def getHosts(ossec_server):
    """Returns a list of all servers connected to an OSSEC server."""
    audited_hosts = {'active_hosts':[], 'dead_hosts': []}
    # Connect to OSSEC server, get a list of all agents.
    hosts = run(
        ['/usr/bin/ssh', ossec_server, 'sudo', '/var/ossec/bin/agent_control',
         '-ls'], encoding='ascii', stdout=PIPE).stdout.split('\n')
    hostnames = []
    for host in hosts:
        if len(host) > 0:
            hostnames.append(host.split(',')[1])
    for hostname in hostnames[1:5]:
        try:
            # Testing DNS resolution and the ability to connect to TCP
            # 22 on remote host.  If these checks fail, add the host
            # to the list of hosts that do not respond.
            host_ip = gethostbyname(hostname)
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(2)
            s.connect((host_ip, 22))
            s.send(b'\n\n')
            data = s.recv(4096)
        except gaierror:
            audited_hosts['dead_hosts'].append(hostname)
            continue
        except timeout:
            audited_hosts['dead_hosts'].append(hostname)
            continue
        if data is not None and len(str(data)) > 0:
            audited_hosts['active_hosts'].append(hostname)
        s.close()
    return audited_hosts


def getADUsers(ossec_server):
    """Connects to ossec server, returns a list of AD users."""
    ad_user_list = []
    # Getting AD users from a file on the OSSEC server.
    ad_users = run(
        ['/usr/bin/ssh', ossec_server, 'sudo', 'cat',
         '/var/ossec/lists/ad_users'], encoding='ascii', stdout=PIPE
         ).stdout.strip('\n').split('\n')
    # Parsing through the file, returning a list of users.
    for user in ad_users:
        ad_user_list.append(user.split(':')[0])
    return ad_user_list


def getTermdUsers(local_users, ad_users):
    """Compares user lists, returns list of users not in AD."""
    t_users = []
    # Getting excluded users.
    ex_file = open('exclusions.list', 'r', encoding='ascii')
    sys_accts = [exclusion.strip('\n') for exclusion in ex_file]
    ex_file.close()
    # Performing list comparison, returning users not in AD.
    for user in local_users:
        if user not in ad_users and user not in sys_accts:
            t_users.append(user)
    return t_users
