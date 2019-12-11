#!/usr/bin/python3
from subprocess import run, PIPE, CalledProcessError
from re import match, search
from socket import gethostbyname, socket, AF_INET, SOCK_STREAM
from socket import gaierror, timeout
from os.path import exists

from cx_Oracle import connect, Error

from validate import validate_un, validate_hn


def get_db_users(user, pwd, db_host):
    """Connects to the database, returns a list of users.

    Keyword Arguments:
    user - str(), The database user to connect as.
    pwd - str(), The user's password.
    db_host - str(), The connection string of the database.

    Outputs:
    db_user_list - list(), A list of database users.

    Raises:
    con_error - Unable to connect to the database.  Prints error
    message, connection error code and exits with a status code
    of 1."""
    try:
        db_connection = connect(user, pwd, db_host)
    except Error as con_error:
        print('Unable to connect to DB. The error message is: %s\n' +
              'The error code is: %s' % (con_error.message, con_error.code))
        exit(1)
    db_cursor = db_connection.cursor()
    query = """SELECT username, profile
               FROM dba_users
               WHERE account_status = 'OPEN'
               ORDER BY username"""
    db_cursor.execute(query)
    db_user_list = []
    for row in db_cursor:
        db_user_list.append(row)
    return db_user_list


def get_dba_ex(kg_admins, dba_profs):
    """Compares two lists, returns exceptions.

    Keyword arguments:
    kg_admins - list(), Known good admin list.
    dba_profs - list(), Users with the DBA profile.

    Outputs:
    dba_ex - list(), Unauthorized accounts with the DBA profile."""
    dba_ex = []
    good_admins = kg_admins
    dba_prof_users = dba_profs
    for user in dba_prof_users:
        if user not in good_admins:
            dba_ex.append(user)
    return dba_ex


def get_users(host):
    """Connect to host, get users, return list of users.

    Keyword arguments:
    host - str(), hostname of remote system.

    Outputs:
    user_list - list(), users with a valid shell."""
    user_list = []
    no_shell = (r'/bin/false$|/sbin/nologin$|/bin/sync$|/sbin/halt$' +
                r'|/sbin/shutdown$|/usr/sbin/nologin$')
    # Connect to remote system, get a list of all user accounts that
    # have an interactive shell.
    file_contents = run(
        ['/usr/bin/ssh', '-oStrictHostKeyChecking=no', host, 'cat',
         '/etc/passwd'], encoding='ascii', stdout=PIPE
         ).stdout.strip('\n').split('\n')
    for line in file_contents:
        shell = line.split(':')[len(line.split(':')) - 1]
        username = line.split(':')[0]
        if not match(no_shell, shell) and validate_un(username):
            user_list.append(line.split(':')[0])
    return user_list


def get_groups(host, mgroup_file_name):
    """Connect to host, get monitored groups, return groups.

    Keyword arguments:
    host - str(), The hostname of the remote system.
    mgroup_file_name - str(), The file that contains the list of users
    to retrieve.

    Outputs:
    monitred_groups - list(), The groups to check."""
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
                m_group_list.append(host_group)
    # Returning monitored groups and their members as a list of
    # dictionaries.
    m_groups.close()
    for m_group in m_group_list:
        monitored_groups.append(
            {m_group.split(':')[0]: m_group.split(':')[3].split(',')}
        )
    return monitored_groups


def get_linux_hosts(user, ossec_server):
    """Returns a list of all Linux servers connected to an OSSEC
    server.

    Keyword arguments:
    user - str(), The user that will be connecting to the remote
    system.
    ossec_server - str(), The ossec server to connect to.

    Outputs:
    audited_hosts = list(), The hosts to audit.

    Raises:
    gaierror - Occurs when DNS resolution of a hostname fails.
    timeout - Occurs when connection via TCP 22 does not occur within
    fie seconds.
    ConnectionRefusedError - Occurs when the remote host actively
    refuses a connetion attempt via TCP 22.
    OSError - Any generic OS errors that occur when attempting to
    connect to the remote host via TCP 22."""
    audited_hosts = {'active_hosts': [], 'dead_hosts': []}
    # Connect to OSSEC server, get a list of all agents.
    hostnames = []
    auth_user = user
    c_string = auth_user + '@' + ossec_server
    if validate_hn(ossec_server):
        hosts = run(
            ['/usr/bin/ssh', c_string, 'sudo',
             '/var/ossec/bin/agent_control', '-ls'], encoding='ascii',
            stdout=PIPE).stdout.split('\n')
    for host in hosts:
        ossec_id = host.split(',')[0]
        host_data = run(
            ['/usr/bin/ssh', ossec_server, 'sudo',
             '/var/ossec/bin/agent_control', '-s', '-i', ossec_id],
            encoding='ascii', stdout=PIPE).stdout.split(',')
        if len(host_data[1]) > 0 and validate_hn(host_data[1]):
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
            s.settimeout(5)
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
        except OSError:
            audited_hosts['dead_hosts'].append(hostname)
            continue
        if data is not None and len(str(data)) > 0:
            audited_hosts['active_hosts'].append(hostname)
        s.close()
    return audited_hosts


def get_aix_hosts(user, ossec_server):
    """Returns a list of all AIX servers connected to an OSSEC server.

    Keyword arguments:
    user - str(), The user that will be connecting to the remote
    system.
    ossec_server - str(), The ossec server to connect to.

    Outputs:
    audited_hosts = list(), The hosts to audit.

    Raises:
    gaierror - Occurs when DNS resolution of a hostname fails.
    timeout - Occurs when connection via TCP 22 does not occur within
    fie seconds.
    ConnectionRefusedError - Occurs when the remote host actively
    refuses a connetion attempt via TCP 22.
    OSError - Any generic OS errors that occur when attempting to
    connect to the remote host via TCP 22."""
    audited_hosts = {'active_hosts': [], 'dead_hosts': []}
    # Connect to OSSEC server, get a list of all agents.
    hostnames = []
    c_string = user + '@' + ossec_server
    if validate_hn(ossec_server):
        hosts = run(
            ['/usr/bin/ssh', c_string, 'sudo',
             '/var/ossec/bin/agent_control', '-ls'], encoding='ascii',
            stdout=PIPE).stdout.split('\n')
    for host in hosts:
        ossec_id = host.split(',')[0]
        host_data = run(
            ['/usr/bin/ssh', c_string, 'sudo',
             '/var/ossec/bin/agent_control', '-s', '-i', ossec_id],
            encoding='ascii', stdout=PIPE).stdout.split(',')
        if len(host_data[1]) > 0 and validate_hn(host_data[1]):
            hd_name = host_data[1]
            hd_os_string = host_data[4]
        if match(r'^AIX', hd_os_string):
            hostnames.append(hd_name)
    if exists('aix_known_hosts.txt'):
        aix_known_hosts = open('aix_known_hosts.txt', 'r', encoding='ascii')
        for aix_host in aix_known_hosts:
            aix_hn = aix_host.strip('\n') + '.24hourfit.com'
            if aix_hn not in hostnames and validate_hn(aix_hn):
                hostnames.append(aix_hn)
        aix_known_hosts.close()
    for hostname in hostnames:
        try:
            # Testing DNS resolution and the ability to connect to TCP
            # 22 on remote host.  If these checks fail, add the host
            # to the list of hosts that do not respond.
            host_ip = gethostbyname(hostname)
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(5)
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


def get_ad_users(user, ossec_server):
    """Connects to ossec server, returns a list of AD users.

    Keyword arguments:
    user - str(), The user that will be connecting to the OSSEC
    server.
    ossec_sever - str(), The ossec server to connect to.

    Outputs:
    ad_user_list - list(), Users in Active Directory."""
    ad_user_list = []
    # Getting AD users from a file on the OSSEC server.
    auth_user = user
    c_string = auth_user + '@' + ossec_server
    if validate_hn(ossec_server):
        ad_users = run(
            ['/usr/bin/ssh', c_string, 'sudo', 'cat',
             '/var/ossec/lists/ad_users'], encoding='ascii', stdout=PIPE
             ).stdout.strip('\n').split('\n')
    else:
        print('Invalid ossec server name.')
        exit(1)
    # Parsing through the file, returning a list of users.
    for user in ad_users:
        username = user.split(':')[0]
        if validate_un(username):
            ad_user_list.append(username)
    return ad_user_list


def get_orphans(local_users, ad_users, exclusion_file):
    """Compares user lists, returns list of users not in AD.

    Keyword arguments:
    local_users - list(), Local users on a system.
    ad_users - list(), Users in active directory
    exclusion_file - file(), A file containing users to exclude from
    the audit.

    Outputs:
    t_users = list(), Users that are on the local system that do not
    have a corresponding AD account."""
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


def rem_orphans(host, orphans):
    """Deletes users not in AD, returns process info.

    Keyword arguments:
    host - str(), The host to connect to.
    orphans - list(), The list of users to remove.

    Outputs:
    data - dict(), Command execution output.

    Raises:
    purge_error - Raised if the execution of userdel ends in a
    non-zero status code.  The data variable is still returned."""
    # Deleting users not in AD.
    for user in orphans:
        try:
            purge = run([
                '/usr/bin/ssh', host, 'sudo', '/usr/sbin/userdel',
                user], stdout=PIPE, stderr=PIPE)
            data = {'r_code': 0, 'output': purge.stdout}
            return data
        except CalledProcessError as purge_error:
            data = {'r_code': purge_error.returncode,
                    'error': purge_error.stderr}
            return data


def getAdminEx(kg_admin_fn, admin_list):
    """Compares admin lists, returns list of exceptions.

    Keyword arguments:
    kg_admin_fn - file(), File name for the file containing known good
    admins.
    admin_list - list(), The list of admins to audit.

    Outputs:
    admin_ex - list(), A list of admin exceptions (e.g., acounts that
    have admin access but are not on the approved list)."""
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
