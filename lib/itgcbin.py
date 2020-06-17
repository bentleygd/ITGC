#!/usr/bin/python3
from re import match, search
from socket import timeout
from logging import getLogger
from ssl import PROTOCOL_TLSv1_2, CERT_NONE
from configparser import ConfigParser
from time import time

from cx_Oracle import connect, Error
from paramiko import SSHClient, WarningPolicy
from paramiko.ssh_exception import SSHException, AuthenticationException
from ldap3 import Connection, Server, SUBTREE, Tls
from ldap3.core.exceptions import LDAPExceptionError

from lib.validate import validate_un, validate_hn
from lib.coreutils import ssh_test, get_credentials


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
        get_audit_ex - Compares local users to AD, returns users not
        in AD."""
        self.host_list = {}
        self.ad_users = []
        self.conf = 'config.cnf'
        self.log = getLogger(__name__)

    def get_ad_users(self):
        """Returns a list of users from specific OUs via LDAPS.

        Outputs:
        user_list - A list of active users in AD.

        Raises:
        OSError - Occurs when the script is unable to locate or open the
        configuration file.  It can also occur when the value used as
        input for the wintime_to_timestr function receives an invalid
        input.
        KeyError - Occurs when a given key in the data_map dictionary does
        not exist.
        LDAPExceptionError - Occurs when the LDAP3 functions generate an
        error.  The base class for all LDAPExcetionErrors is used so that
        the log.exception call will catch the detailed exception while not
        missing any potential exceptions.  A fail safe, as it were."""
        # Setting logging
        # Setting configuration.
        config = ConfigParser()
        try:
            config.read(self.conf)
        except OSError:
            self.log.exception(
                'Fatal Error: Unable to open configuration file.'
            )
            exit(1)
        ldap_url = config['ldap']['url']
        ldap_bind_dn = config['ldap']['bind_dn']
        search_ou = config['ldap']['search_ou'].split('|')
        ldap_bind_secret = get_credentials({
            'api_key': config['ldap']['scss_api'],
            'otp': config['ldap']['scss_otp'],
            'userid': config['ldap']['scss_user'],
            'url': config['ldap']['scss_url']
        })
        # Connecting to LDAP.  Raising an exception with logging if the
        # connection is unsuccessful.
        start = time()
        tls_config = Tls(validate=CERT_NONE, version=PROTOCOL_TLSv1_2)
        server = Server(ldap_url, use_ssl=True, tls=tls_config)
        try:
            conn = Connection(
                server,
                user=ldap_bind_dn,
                password=ldap_bind_secret,
                auto_bind=True
            )
        except LDAPExceptionError:
            self.log.exception('Error occurred connecting to LDAP server.')
        self.log.debug('Successfully connected to LDAP server: %s', ldap_url)
        # Getting user data from LDAP, and converting the data (a list
        # of strings) to a dictionary so that it can be easily written
        # to different outputs if so desired.
        user_list = []
        raw_user_data = []
        # Searching LDAP for users that are in the OUs (and all sub-OUs)
        # specified in config['ldap']['search_ou'].
        ldap_filter = ('(&(objectClass=user)(objectCategory=CN=Person,' +
                       'CN=Schema,CN=Configuration,DC=24hourfit,DC=com))')
        for ou in search_ou:
            user_data = conn.extend.standard.paged_search(
                ou,
                ldap_filter,
                search_scope=SUBTREE,
                attributes=['employeeID', 'sAMAccountName'],
                paged_size=500,
            )
            for raw_data in user_data:
                raw_user_data.append(raw_data['raw_attributes'])
        # Mapping LDAP data to a dictionary.  We are decoding the values
        # so that Python recognizes them as a string instead of byte-like
        # objects for compatibiltiy with other string (or string realted)
        # functions/methods.
        for data in raw_user_data:
            # Setting data to none if the value does not exist to avoid
            # IndexError exceptions when parsing the data below.
            if len(data['employeeID']) == 0:
                data.update({'employeeID': [b'None']})
            try:
                data_map = {
                    'Emp_ID': data['employeeID'][0].decode(),
                    'Account_Name': data['sAMAccountName'][0].decode()
                }
            # Exception handling and logging for troubleshooting.
            except KeyError:
                self.log.exception(
                    'Key error occurred for %s when creating data map.',
                    data['name'][0].lower().decode(errors='ignore')
                )
            user_list.append(data_map['Account_Name'])
        self.log.info(
            'Successfully retrieved active user information from %s',
            config['ldap']['url']
        )
        # Unbinding the LDAP object as a good house cleaning measure.
        conn.unbind()
        end = time()
        _elapsed = end - start
        elapsed = int(round(_elapsed, 0))
        self.log.debug('Retrieved active users in %d seconds', elapsed)
        for user in user_list:
            self.ad_users.append(user)
        return user_list

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
        self.log.info('Audit exception generation complete.')
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
        self.log.debug('DB list generated.')
        for _db_name in db_names:
            # Connecting to the DB.
            try:
                db_connection = connect(self.db_user, db_pwd, _db_name)
                # Populating host lists.
                if db_connection:
                    self.host_list['active_dbs'].append(_db_name)
                    db_connection.close()
                    self.log.debug('Succesfully connected to %s', _db_name)
            except Error:
                self.host_list['dead_dbs'].append(_db_name)
                self.log.exception('Unable to connect to %s', _db_name)
            # Closing the DB connection.
        self.log.debug('DB audit list generated')
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
            self.log.debug('Successfully connected to %s', db_host)
        except Error:
            self.log.exception('Unable to connect to %s', db_host)
            exit(1)
        db_cursor = db_connection.cursor()
        # Executing query
        query = """SELECT username, profile
                   FROM dba_users
                   ORDER BY username"""
        self.log.debug('Executing query to retrieve users for %s', db_host)
        db_cursor.execute(query)
        self.log.debug('User query successfully executed for %s', db_host)
        # Iterating over query, converting them to a dict(), appending
        # them to a list.
        self.log.debug('Generating DB user dictionary.')
        for row in db_cursor:
            user_data = {'username': row[0], 'profile': row[1]}
            if validate_un(user_data['username']):
                db_users.append(user_data)
        # Closing the DB connection.
        db_connection.close()
        self.log.info('DB users succesfully retrieved for %s', db_host)
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
        except Error:
            self.log.exception('Unable to connect to DB.')
            exit(1)
        db_cursor = db_connection.cursor()
        self.log.debug('Executing query for granted roles for %s', db_host)
        # Executing query
        query = """SELECT grantee, granted_role, admin_option, default_role
                   FROM dba_role_privs
                   ORDER BY grantee, granted_role"""
        db_cursor.execute(query)
        self.log.debug('Granted role query excecuted for %s', db_host)
        # Iterating over results, converting them to a dict(), writing
        # to a list.
        for row in db_cursor:
            user_data = {
                'username': row[0], 'granted_role': row[1],
                'admin_option': row[2], 'default_role': row[3]
                }
            if validate_un(user_data['username']):
                db_granted_roles.append(user_data)
        # Closing the DB connection.
        db_connection.close()
        self.log.info('DB granted roles retrieved for %s', db_host)
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
        self.log.info('DBA exceptions generated.')
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
        self.log.info('Bad profile exceptions generated.')
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
        local_users - list(), users with a valid shell.

        Raises:
        AuthenticationException - Occurs when SSH authentication fails.
        SSHException - Occurs when there is an SSH error.
        timeout - Occurs when the connection times out after five
        seconds."""
        no_shell = (r'/bin/false$|/sbin/nologin$|/bin/sync$|/sbin/halt$' +
                    r'|/sbin/shutdown$|/usr/sbin/nologin$')
        # Connect to remote system, get a list of all user accounts that
        # have an interactive shell.
        local_users = []
        client = SSHClient()
        client.set_missing_host_key_policy(WarningPolicy)
        client.load_system_host_keys()
        try:
            client.connect(host, timeout=5)
            _in, out, err = client.exec_command('/bin/cat /etc/passwd')
            for line in out:
                line = line.strip('\n')
                shell = line.split(':')[len(line.split(':')) - 1]
                username = line.split(':')[0]
                if not match(no_shell, shell) and validate_un(username):
                    local_users.append(line.split(':')[0])
        except AuthenticationException:
            self.log.exception('Authentication failed for %s', host)
            return 'Authentication Failed.'
        except SSHException:
            self.log.exception(
                'Unable to get local users for %s.  The error is %s.',
                host, err
                )
            return 'SSH Error.  Please investigate.'
        except timeout:
            self.log.exception('Timeout to %s', host)
            return 'Connection timed out after 5 seconds.'
        client.close()
        self.log.info('Local users retreived for %s', host)
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
        client.set_missing_host_key_policy(WarningPolicy)
        client.load_system_host_keys()
        try:
            client.connect(host, timeout=5)
            _in, out, err = client.exec_command('/bin/cat /etc/group')
            for line in out:
                host_groups.append(line.strip('\n'))
            for group in monitored_groups:
                r_exp = r'^' + str(group) + r'.+\d{4,6}:'
                for host_group in host_groups:
                    if (search(r_exp, host_group) and
                        host_group.split(':')[3] is not None and
                            len(host_group.split(':')[3]) > 0):
                        m_group_list.append(host_group)
        except AuthenticationException:
            self.log.exception('Authentication failed for %s.', host)
            return 'Authentication Failed.'
        except SSHException:
            self.log.exception(
                'Unable to get groups for %s.  The error is %s.',
                host, err
                )
            return 'SSH Error.  Please investigate.'
        except timeout:
            print('Timeout to %s', host)
            return 'Connection timed out after 5 seconds.'
        client.close()
        # Returning monitored groups and their members as a list of
        # dictionaries.
        for m_group in m_group_list:
            audited_groups.append(
                {m_group.split(':')[0]: m_group.split(':')[3].split(',')}
            )
        self.log.info('Audited groups retrieved for %s', host)
        return audited_groups

    def get_hosts(self, ossec_server):
        """Returns a list of all Linux servers connected to an OSSEC
        server.

        Keyword arguments:
        user - str(), The user that will be connecting to the remote
        system.
        ossec_server - str(), The ossec server to connect to.

        Outputs:
        audited_hosts = list(), The hosts to audit.

        Raises:
        SSH Exception - Occurs when there is a SSH error."""
        self.host_list = {'active_hosts': [], 'dead_hosts': []}
        # Connect to OSSEC server, get a list of all agents.
        host_data = []
        hosts = []
        hostnames = set()
        ossec_client = SSHClient()
        ossec_client.load_system_host_keys()
        if validate_hn(ossec_server):
            try:
                ossec_client.connect(ossec_server)
                _in, out, err = ossec_client.exec_command(
                    '/usr/bin/sudo /var/ossec/bin/agent_control -ls'
                )
            except AuthenticationException:
                self.log.exception(
                    'Authentication failed to %s', ossec_server
                    )
                exit(1)
            except SSHException:
                self.log.exception(
                    'Unable to retrieve host list from %s. The error is %s',
                    ossec_server, err
                )
            for line in out:
                ossec_id = line.strip('\n').split(',')[0]
                if (ossec_id != '000' and
                        match(r'\d{4,6}', ossec_id)):
                    hosts.append(line.strip('\n'))
            for host in hosts:
                ossec_id = host.split(',')[0]
                try:
                    _in, out, err = ossec_client.exec_command(
                        '/usr/bin/sudo /var/ossec/bin/agent_control -s -i ' +
                        ossec_id
                    )
                except SSHException:
                    self.log.exception(
                        'Unable to retrieve host info for %s. Error: %s',
                        host, err
                    )
                for line in out:
                    host_data = line.split(',')
                    if len(host_data[1]) > 0 and validate_hn(host_data[1]):
                        hd_name = host_data[1]
                        hd_os_string = host_data[4]
                    if self.os == 'Linux':
                        if not match(r'^AIX', hd_os_string):
                            hostnames.add(hd_name)
                    elif self.os == 'AIX':
                        if match(r'^AIX', hd_os_string):
                            hostnames.add(hd_name)
        ossec_client.close()
        for hostname in hostnames:
            if ssh_test(hostname):
                self.host_list['active_hosts'].append(hostname)
            else:
                self.host_list['dead_hosts'].append(hostname)
        self.log.debug('Host list retrieved from %s', ossec_server)
        return self.host_list

    def get_admin_ex(self, known_admins, host_admins):
        """Compares admin lists, returns list of exceptions.

        Keyword arguments:
        known_admins - list(), Known good admins.
        host_admins - list(), The list of admins to audit.

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
        self.log.info('Admin exceptions generated.')
        return admin_ex
