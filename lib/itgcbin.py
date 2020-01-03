#!/usr/bin/python3
from re import match, search

from cx_Oracle import connect, Error
from paramiko import SSHClient, AutoAddPolicy
from paramiko import (SSHException, BadHostKeyException,
                      AuthenticationException)

from lib.validate import validate_un, validate_hn


class ITGCAudit:
    def __init__(self):
        """Creates an Audited System object.

        Keyword arguments:
        None.

        Instance variables:
        host_list - list(), The list of hosts that is audited by the
        object.
        ad_users - list(), Users in AD.

        Methods:
        get_ad_users - Connects to ossec server, returns a list of AD
        users.
        get_audit_ex - Compares local users to AUD, returns users not
        in AD."""
        self.host_list = {}
        self.ad_users = []

    def get_ad_users(self, user, ossec_server):
        """Connects to ossec server, returns a list of AD users.

        Keyword arguments:
        user - str(), The user that will be connecting to the OSSEC
        server.
        ossec_sever - str(), The ossec server to connect to.

        Outputs:
        ad_user_list - list(), Users in Active Directory."""
        # Getting AD users from a file on the OSSEC server.
        auth_user = user
        client = SSHClient()
        client.load_system_host_keys()
        if validate_hn(ossec_server):
            client.connect(ossec_server, username=auth_user)
            try:
                _in, out, err = client.exec_command(
                    '/bin/sudo /bin/cat /var/ossec/lists/ad_users'
                )
            except SSHException:
                print('Unable to retrieve AD users.  The error is:', err)
                exit(1)
            client.close()
            ad_users = []
            for line in out:
                ad_users.append(line.strip('\n'))
        else:
            print('Invalid ossec server name.')
            exit(1)
        # Parsing through the file, returning a list of users.
        for user in ad_users:
            username = user.split(':')[0]
            if validate_un(username):
                self.ad_users.append(username)
        return self.ad_users

    def get_audit_ex(self, local_users, ad_users, exclusions):
        """Compares user lists, returns list of users not in AD.

        Keyword arguments:
        local_users - list(), Local users on a system.
        ad_users - list(), Users in active directory
        exclusions - list(), Users to exclude from the audit.

        Outputs:
        audit_ex = list(), Users that are on the local system that do
        not have a corresponding AD account."""
        audit_ex = []
        # Performing list comparison, returning users not in AD.
        for user in local_users:
            if (user.lower() not in ad_users and
                    user.lower() not in exclusions):
                audit_ex.append(user)
        return audit_ex


class OracleDBAudit(ITGCAudit):
    def __init__(self):
        """Oracle DB audit object

        Keyword Arguments:
        None

        Instance variables:
        db_user - str(), The user used to authenticate to the Oracle
        DB and perform the audit.

        Methods:
        get_db_users - Retrieves all users from the dba_user table.
        get_db_granted_roles - Retrieves all granted roles from the
        dba_role_privs table.
        get_db_list - Generates a list of reachable and unreachable
        DBs.
        get_admin_ex - Generates a list of unauthorized users with DBA
        priviledges.
        get_bad_profiles - Generates a list of human users with the
        schema profile and a list of users with the default profile.
        """
        # Calling the parent's init to include parent's instance
        # variables.
        ITGCAudit.__init__(self)
        self.db_user = str()

    def get_db_list(self, _file, db_pwd, env):
        """Parses a tnsnames.ora file, returns DB host info.

        Keyword Arguments:
        tns_file - str(), The location of the tnsnames.ora file.
        db_pwd - str(), The password to log in to the DB.
        env - str(), The environment to audit (i.e., production or
        non-production).

        Outputs:
        host_lost - Dict(), a dictionary containing reachable and
        unreachable DBs."""
        # Variable initialization.
        db_names = []
        self.host_list = {'active_dbs': [], 'dead_dbs': []}
        # Parsing through tnsnames.ora to make a list of DBs to
        # connect to.
        tns_file = open(_file, 'r', encoding='ascii')
        for line in tns_file:
            db_parse = search(r'(^\S{4,12}) =', line)
            if db_parse:
                dbname = db_parse.group(1)
                if env == 'NPRD':
                    if 'QA' in dbname or 'DEV' in dbname:
                        db_names.append(dbname)
                elif env == 'PRD':
                    if 'QA' not in dbname and 'DEV' not in dbname:
                        db_names.append(dbname)
        for _db_name in db_names:
            # Connecting to the DB.
            try:
                db_connection = connect(self.db_user, db_pwd, _db_name)
                # Populating host lists.
                if db_connection:
                    self.host_list['active_dbs'].append(_db_name)
                    db_connection.close()
            except Error:
                self.host_list['dead_dbs'].append(_db_name)
            # Closing the DB connection.
        return self.host_list

    def get_db_users(self, pwd, db_host):
        """Connects to the database, returns a list of users.

        Keyword Arguments:
        pwd - str(), The user's password.
        db_host - str(), The DB SID.

        Outputs:
        db_user_list - list(), A list of database user dictionaries
        containg the username and the profile of the user.

        Raises:
        con_error - Unable to connect to the database.  Prints error
        message and exits with a status code of 1."""
        db_users = []
        try:
            # Connecting to DB
            db_connection = connect(self.db_user, pwd, db_host)
        except Error as con_error:
            conError, = con_error.args
            print('Unable to connect to', db_host + '\nThe error is:',
                  conError.message)
            exit(1)
        db_cursor = db_connection.cursor()
        # Executing query
        query = """SELECT username, profile
                   FROM dba_users
                   ORDER BY username"""
        db_cursor.execute(query)
        # Iterating over query, converting them to a dict(), appending
        # them to a list.
        for row in db_cursor:
            user_data = {'username': row[0], 'profile': row[1]}
            db_users.append(user_data)
        # Closing the DB connection.
        db_connection.close()
        return db_users

    def get_db_granted_roles(self, pwd, db_host):
        """Connects to the database, returns a list of users.

        Keyword Arguments:
        user - str(), The database user to connect as.
        pwd - str(), The user's password.
        db_host - str(), The connection string of the database.

        Outputs:
        db_user_list - list(), A list of database user dictionaries
        containg the granted role(s) of the user.

        Raises:
        con_error - Unable to connect to the database.  Prints error
        message and exits with a status code of 1."""
        db_granted_roles = []
        # Connecting to DB
        try:
            db_connection = connect(self.db_user, pwd, db_host)
        except Error as con_error:
            conError, = con_error.args
            print('Unable to connect to DB. The error is:', conError.message)
            exit(1)
        db_cursor = db_connection.cursor()
        # Executing query
        query = """SELECT grantee, granted_role, admin_option, default_role
                   FROM dba_role_privs
                   ORDER BY grantee, granted_role"""
        db_cursor.execute(query)
        # Iterating over results, converting them to a dict(), writing
        # to a list.
        for row in db_cursor:
            user_data = {
                'username': row[0], 'granted_role': row[1],
                'admin_option': row[2], 'default_role': row[3]
                }
            db_granted_roles.append(user_data)
        # Closing the DB connection.
        db_connection.close()
        return db_granted_roles

    def get_admin_ex(self, known_admins, db_admins):
        """Compares two lists, returns a list of exceptions.

        Keyword arguments:
        known_admins - list(), Known admins who are approved to have
        admin level privileges.
        db_admins - list(), Admins from an audited database.

        Outputs:
        admin_ex - list(), Users who are not approved to have admin
        access."""
        # Iterating over admin users from host, comparing them to
        # known good, returing any exceptions as a list.
        admin_ex = []
        for user in set(db_admins):
            if (user.lower() not in known_admins and
                    user.lower() not in admin_ex):
                admin_ex.append(user)
        return admin_ex

    def get_bad_profiles(self, db_users):
        """Compares AD users to users with schema prof and enumerates
        users that have the default profile.

        Keyword arguments:
        db_users - list(), A list of db_users and profiles.

        Outputs:
        bad_profiles - dict (), A list of human users with the schema
        profile and a list of all users with the default profile."""
        bad_profiles = {'schema_prof': [], 'default_prof': []}
        for user in db_users:
            if (user['username'].lower() in self.ad_users and
                    user['profile'] == 'SCHEMA_PROF'):
                bad_profiles['schema_prof'].append(user['username'])
        for user in db_users:
            if user['profile'] == 'DEFAULT' and user['username'] != 'XS$NULL':
                bad_profiles['default_prof'].append(user['username'])
        return bad_profiles


class UnixHostAudit(ITGCAudit):
    def __init__(self, os):
        """A UnixAudit object.

        Keyword Arugments:
        os - The operating system (e.g., Linux)

        Instance variables:
        os - The opertating sytem that is going to be audited.

        Methods:
        get_users - Connects to host and generates a list of local
        users.
        get_groups - Connect to host and generates a list of users
        in specific groups.
        get_hosts - Connect to the OSSEC server and gather a list of
        audited hosts based on OS (AIX or Linux).
        get_admin_ex - Connects to host and compares local admins
        against a list of known admins.  Returns the difference."""
        ITGCAudit.__init__(self)
        self.os = os

    def get_users(self, host):
        """Connect to host, get users, return list of users.

        Keyword arguments:
        host - str(), hostname of remote system.

        Outputs:
        local_users - list(), users with a valid shell."""
        no_shell = (r'/bin/false$|/sbin/nologin$|/bin/sync$|/sbin/halt$' +
                    r'|/sbin/shutdown$|/usr/sbin/nologin$')
        # Connect to remote system, get a list of all user accounts that
        # have an interactive shell.
        local_users = []
        client = SSHClient()
        client.load_system_host_keys()
        client.connect(host)
        try:
            _in, out, err = client.exec_command('/bin/cat /etc/passwd')
        except SSHException:
            print('Unable to get local users. The error is:', err)
            exit(1)
        except AuthenticationException:
            local_users.append('Authentication_Failed')
        client.close()
        for line in out:
            line = line.strip('\n')
            shell = line.split(':')[len(line.split(':')) - 1]
            username = line.split(':')[0]
            if not match(no_shell, shell) and validate_un(username):
                local_users.append(line.split(':')[0])
        return local_users

    def get_groups(self, host, monitored_groups):
        """Connect to host, get all groups, return monitored groups.

        Keyword arguments:
        host - str(), The hostname of the remote system.
        monitored_groups - list(), The list of admin groups to monitor.

        Outputs:
        audited_groups - list(), The groups to check."""
        m_group_list = []
        audited_groups = []
        # Obtaining members of monitored groups from a remote host.
        host_groups = []
        client = SSHClient()
        client.load_system_host_keys()
        client.connect(host)
        try:
            _in, out, err = client.exec_command('/bin/cat /etc/group')
        except SSHException:
            print('Unable to get groups. The error is:', err)
            exit(1)
        client.close()
        for line in out:
            host_groups.append(line.strip('\n'))
        for group in monitored_groups:
            r_exp = r'^' + str(group) + r'.+\d{4,6}:'
            for host_group in host_groups:
                if (search(r_exp, host_group) and
                    host_group.split(':')[3] is not None and
                        len(host_group.split(':')[3]) > 0):
                    m_group_list.append(host_group)
        # Returning monitored groups and their members as a list of
        # dictionaries.
        for m_group in m_group_list:
            audited_groups.append(
                {m_group.split(':')[0]: m_group.split(':')[3].split(',')}
            )
        return audited_groups

    def get_hosts(self, user, ossec_server):
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
        timeout - Occurs when connection via TCP 22 does not occur
        within five seconds.
        ConnectionRefusedError - Occurs when the remote host actively
        refuses a connetion attempt via TCP 22.
        OSError - Any generic OS errors that occur when attempting to
        connect to the remote host via TCP 22."""
        self.host_list = {'active_hosts': [], 'dead_hosts': []}
        # Connect to OSSEC server, get a list of all agents.
        hostnames = []
        auth_user = user
        ossec_client = SSHClient()
        ossec_client.load_system_host_keys()
        if validate_hn(ossec_server):
            ossec_client.connect(ossec_server, username=auth_user)
            try:
                _in, out, err = ossec_client.exec_command(
                    '/bin/sudo /var/ossec/bin/agent/control -ls'
                )
            except SSHException:
                print('Unable to retrieve host list. The error is:', err)
        hosts = set()
        for line in out:
            hosts.add(line.strip('\n'))
        for host in hosts:
            ossec_id = host.split(',')[0]
            if not match(r'\d{4,6}', ossec_id):
                print('Invalid OSSEC ID.  Aborting')
                exit(1)
            try:
                _in, out, err = ossec_client.exec_command(
                    '/bin/sudo /var/ossec/bin/agent_control -s -i ' + ossec_id
                )
            except SSHException:
                print('Unable to retrieve host info. The error is:', err)
            host_data = []
            for line in out:
                host_data.append(line.strip('\n'))
            if len(host_data[1]) > 0 and validate_hn(host_data[1]):
                hd_name = host_data[1]
                hd_os_string = host_data[4]
            if self.os == 'Linux':
                if not match(r'^AIX', hd_os_string):
                    hostnames.append(hd_name)
            elif self.os == 'AIX':
                if match(r'^AIX', hd_os_string):
                    hostnames.append(hd_name)
        ossec_client.close()
        client = SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(AutoAddPolicy)
        for hostname in hostnames:
            try:
                # Testing DNS resolution, the ability to connect to TCP
                # 22 on the remote host and initial authentication.
                # If these checks fail, add the host to the list of
                # hosts that do not respond.
                client.connect(hostname, banner_timeout=5, auth_timeout=5)
            except BadHostKeyException:
                self.host_list['dead_hosts'].append(hostname)
                continue
            except AuthenticationException:
                self.host_list['dead_hosts'].append(hostname)
                continue
            except SSHException:
                self.host_list['dead_hosts'].append(hostname)
            except ConnectionRefusedError:
                self.host_list['dead_hosts'].append(hostname)
                continue
            except OSError:
                self.host_list['dead_hosts'].append(hostname)
                continue
            if client.connect:
                self.host_list['active_hosts'].append(hostname)
            client.close()
        return self.host_list

    def get_admin_ex(self, known_admins, host_admins):
        """Compares admin lists, returns list of exceptions.

        Keyword arguments:
        known_admins - list(), dict() objects containing known admins.
        admin_list - list(), The list of admins to audit.

        Outputs:
        admin_ex - list(), A list of admin exceptions (e.g., accounts
        that have admin access but are not on the approved list)."""
        admin_ex = []
        for known_admin in known_admins:
            for admins in host_admins:
                tested_group = known_admin.split(':')[0]
                if tested_group in admins:
                    audit_finding = {tested_group: []}
                    known_admins = known_admin.split(':')[1]
                    for admin in admins.get(tested_group):
                        if admin not in known_admins:
                            audit_finding[tested_group].append(admin)
                    admin_ex.append(audit_finding)
        return admin_ex
