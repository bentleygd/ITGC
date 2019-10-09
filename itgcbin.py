#!/usr/bin/python3
from subprocess import run, PIPE
from re import match, search
from socket import gethostbyname, socket, AF_INET, SOCK_STREAM
from socket import gaierror, timeout

from validate import ValidateUN, ValidateHN


def getUsers(host):
    """Connect to host, get users, return list of users."""
    user_list = []
    no_shell = (r'/bin/false$|/sbin/nologin$|/bin/sync$|/sbin/halt$' +
                r'|/sbin/shutdown$')
    # Connect to remote system, get a list of all user accounts that
    # have an interactive shell.
    file_contents = run(
        ['/usr/bin/ssh', '-oStrictHostKeyChecking=no', host, 'cat',
         '/etc/passwd'], encoding='ascii', stdout=PIPE
         ).stdout.strip('\n').split('\n')
    for line in file_contents:
        shell = line.split(':')[len(line.split(':')) - 1]
        username = line.split(':')[0]
        if not match(no_shell, shell) and ValidateUN(username):
            user_list.append(line.split(':')[0])
    return user_list


def getGroups(host, mgroup_file_name):
    """Connect to host, get monitored groups, return groups."""
    groups = []
    m_group_list = []
    monitored_groups = []
    # Obtaining groups to monitor.
    m_groups = open(mgroup_file_name, mode='r', encoding='ascii')
    # Obtaining members of monitored groups from a remote host.
    host_groups = run(
        ['/usr/bin/ssh', host, 'cat', '/etc/group'],
        encoding='ascii', stdout=PIPE
        ).stdout.strip('\n').split('\n')
    groups = [line.strip('\n') for line in m_groups]
    for group in groups:
        r_exp = r'^' + str(group) + r'.+\d{4,6}:'
        for host_group in host_groups:
            if (search(r_exp, host_group) and
                host_group.split(':')[3] is not None and
                len(host_group.split(':')[3]) > 0):
                # If all are true, append.
                m_group_list.append(host_group)
    # Returning monitored groups and their members as a list of
    # dictionaries.
    m_groups.close()
    for m_group in m_group_list:
        monitored_groups.append(
            {m_group.split(':')[0]: m_group.split(':')[3].split(',')}
        )
    return monitored_groups


def getLinuxHosts(ossec_server):
    """Returns a list of all servers connected to an OSSEC server."""
    audited_hosts = {'active_hosts': [], 'dead_hosts': []}
    # Connect to OSSEC server, get a list of all agents.
    hostnames = []
    if ValidateHN(ossec_server):
        hosts = run(
            ['/usr/bin/ssh', ossec_server, 'sudo',
             '/var/ossec/bin/agent_control', '-ls'], encoding='ascii',
            stdout=PIPE).stdout.split('\n')
    for host in hosts:
        ossec_id = host.split(',')[0]
        host_data = run(
            ['/usr/bin/ssh', ossec_server, 'sudo',
             '/var/ossec/bin/agent_control', '-s', '-i', ossec_id],
            encoding='ascii', stdout=PIPE).stdout.split(',')
        if len(host_data[1]) > 0 and ValidateHN(host_data[1]):
            hd_name = host_data[1]
            hd_os_string = host_data[4]
        if not match(r'^AIX', hd_os_string):
            hostnames.append(hd_name)
    for hostname in hostnames:
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
        except ConnectionRefusedError:
            audited_hosts['dead_hosts'].append(hostname)
            continue
        if data is not None and len(str(data)) > 0:
            audited_hosts['active_hosts'].append(hostname)
        s.close()
    return audited_hosts


def getAIXHosts(ossec_server):
    """Returns a list of all servers connected to an OSSEC server."""
    audited_hosts = {'active_hosts': [], 'dead_hosts': []}
    # Connect to OSSEC server, get a list of all agents.
    hostnames = []
    if ValidateHN(ossec_server):
        hosts = run(
            ['/usr/bin/ssh', ossec_server, 'sudo',
             '/var/ossec/bin/agent_control', '-ls'], encoding='ascii',
            stdout=PIPE).stdout.split('\n')
    for host in hosts:
        ossec_id = host.split(',')[0]
        host_data = run(
            ['/usr/bin/ssh', ossec_server, 'sudo',
             '/var/ossec/bin/agent_control', '-s', '-i', ossec_id],
            encoding='ascii', stdout=PIPE).stdout.split(',')
        if len(host_data[1]) > 0 and ValidateHN(host_data[1]):
            hd_name = host_data[1]
            hd_os_string = host_data[4]
        if match(r'^AIX', hd_os_string):
            hostnames.append(hd_name)
    for hostname in hostnames:
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
        except ConnectionRefusedError:
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
    if ValidateHN(ossec_server):
        ad_users = run(
            ['/usr/bin/ssh', ossec_server, 'sudo', 'cat',
             '/var/ossec/lists/ad_users'], encoding='ascii', stdout=PIPE
             ).stdout.strip('\n').split('\n')
    else:
        print('Invalid ossec server name.')
        exit(1)
    # Parsing through the file, returning a list of users.
    for user in ad_users:
        username = user.split(':')[0]
        if ValidateUN(username):
            ad_user_list.append(username)
    return ad_user_list


def getOrphans(local_users, ad_users, exclusion_file):
    """Compares user lists, returns list of users not in AD."""
    t_users = []
    # Getting excluded users.
    ex_file = open(exclusion_file, 'r', encoding='ascii')
    sys_accts = [exclusion.strip('\n') for exclusion in ex_file]
    ex_file.close()
    # Performing list comparison, returning users not in AD.
    for user in local_users:
        if user not in ad_users and user not in sys_accts:
            t_users.append(user)
    return t_users


def getAdminEx(kg_admin_fn, admin_list):
    """Compares admin lists, returns list of exceptions."""
    admin_ex = []
    # audit_findinddg = []
    kg_admin_file = open(kg_admin_fn, 'r', encoding='ascii')
    kg_admins = [kg_admin.strip('\n') for kg_admin in kg_admin_file]
    kg_admin_file.close()
    for kg_admin in kg_admins:
        for admins in admin_list:
            tested_group = kg_admin.split(':')[0]
            if tested_group in admins:
                audit_finding = {tested_group: []}
                known_admins = kg_admin.split(':')[1]
                for admin in admins.get(tested_group):
                    if admin not in known_admins:
                        audit_finding[tested_group].append(admin)
                admin_ex.append(audit_finding)
    return admin_ex
