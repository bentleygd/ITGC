# ITGCLIB Documentation

<h2>ITGCLIB Classes</h2>
<h2>ITGCAudit</h2>
The ITGCAudit class is a base class that is meant to be inherited by sub-classes to allow those sub-classes to be able to use the class methods and instances variables (detailed below).  This is done to reduce duplicate code.

**Class Methods**:  
- **ITGCAudit.get_ad_users** \- This method retrieves users from specific OUs (specified in the [ldap][search_ou] portion of the configuration) and stores them in the self.ad_users variable.  It returns the self.ad_users variable as user_list.  
- **ITGCAudit.get_audit_ex** \- This method performs a list comparison and appends the delta to the audit_ex variable (a list).  The audit_ex variable is returned when this method is called.  

**Class Variables**:  
- **ITGCAudit.host_list** \- A dictionary object that contains a list object of reachable hosts and a list object of unreachable hosts.  This attribute is utilized by the sub-classes of the ITGCAudit class.  
- **ITGCAudit.ad_users** \- A list object that contains the users from AD that are gathered by the get_ad_users() method.  
- **ITGCAudit.conf** \- A string that represents the location of a configuration file that is called by the ConfigParser class (specifically, ConfigParser.read()) from the configparser module.  An example configuration is provided in example.conf.  
- **ITGCAudit.log** \- A call to the getLogger function from the logging module.  This allows for easy logging calls by referencing self.log in subclasses.

<h3>ITGCAudit Method Documentation</h3>  

**get_ad_users()**

Keyword Arguments:  
- None.

Returns:  
- user_list \- a list object containing all users from the OUs specified in [ldap][search_ou] section of the configuration.

Rasies:
- OSError \- Occurs when the script is unable to locate or open the configuration file.
- LDAPExceptionError \- Occurs when the LDAP3 functions generate an error.  The base class for all LDAPExcetionErrors is used so that the log.exception call will catch the detailed exception while not missing any potential exceptions.  

**Code Example**:  

```python
    from lib.itgcbin import ITGCAudit


    audit_obj = ITGCAudit()
    ad_users = audit_obj.get_ad_users()

    for user in ad_users:
        print('This is a user from active directory', user)
```

**get_audit_ex**(local_users, ad_users, exclusions) 

Keyword Arguments:
- local_users - A list object containing all the users from a local system.  
- ad_users - A list object containing the users from active directory.  
- exclusions - A list object of user IDs that are excluded from the audit.  

Returns:
- audit_ex, a list object containing exceptions from a list comparison.  



**Code Example**
```python
    from lib.itgcbin import ITGCAudit


    audit_obj = ITGCAudit()
    ad_users = audit_obj.get_ad_users()
    local_accounts = ['bob', 'alice', 'tom']
    excluded_users = ['tom'] # Exclusions are normally obtained from the config.
    no_ad_account = audit_obj.get_audit_ex(
        local_accounts, ad_users, excluded_users
    )
    for bad_user in no_ad_account:
        print('%s does not have an AD account.', bad_user)
```  
<h2>OracleDBAudit</h2>
The OracleDBAudit class is a sub-class of the ITGCAudit class.  This class is designed to be able to automate user security reviews of Oracle databases.  This is accomplished using the cx-Oracle module, which relies on an Oracle client library.  Care should be taken in which Oracle client library is used as some Oracle client libraries require a license from Oracle.  

**Class Methods**  
- **OracleDBAudit.get_db_users** \- This method retrieves all users (and their profile) from the dba_user table, appends them (as a dictionary with the keys of 'username' and profile') to the db_users list object and returns db_users when the method is called.
- **OracleDBAudit.get_db_granted_roles** \- This method retrieves all users (and their granted roles) from the dba_role_privs table, appends them (as a dictionary with the keys of 'username', 'granted_role', 'admin_option', and 'default_role') to the db_granted_roles list object and returns db_granted_roles when the method is called.
- **OracleDBAudit.get_db_list** \- This method generates a list of reachable and unreachable DBs by parsing a tnsnames.ora file and attempting to connect to the database with the password passed to the method when it is called.  The method requires that an environment be specified to function correctly.  By default, the enivronments supported are PRD, QA and DEV.  The code in this method may need to be modified to match your environment labels.
- **OracleDBAudit.get_admin_ex** \- This method generates a list of unauthorized users with DBA priviledges by comparing users with an administrative granted role to a static list of known admins.  This is dependent upon the list specified in [oracle][known_admins] portion of the configuration as well as the results of the get_db_granted_roles method.  
- **OracleDBAudit.get_bad_profiles** \- This method generates a list of human users with the SCHEMA_PROF profile and a list of users with the default profile.  In this case, "human" users are determined by the list of users that are obtained from Active Directory using the get_ad_users method that is inherited from the ITGCAudit class.  

**Class Variables**  
- **OracleDBAudit.db_user** \- A string object which represents the user used to authenticate to the Oracle databses.  This value is referenced by the following methods in OracleDBAudit: **get_db_users**, **get_db_list**, **get_db_granted_roles**.  

<h3>OracleDBAudit Method Documentation</h3>  

**get_db_users**(pwd, db_host)

Keyword Arguments:  
- pwd \- A string that reprsents the password that will be used to connect to the datbase/
- db_host \- A string that is the Oracle DB's SID.

Returns:  
- db_users \- A list of dictionary objects containg the username and the profile for each user.

Raises:  
- Error \- The base class for exceptions for the cx_oracle module.  This occurs when anything goes wrong connecting to the the target DB.  The base class is used in order to be able to catch any sub-exception, the details of which would be logged.  

Code Example:
```python
    from lib import itgcbin


    db_audit = itgcbin.OracleDBAudit()
    # Retrieving data from the config.
    db_audit.db_user = config['oracle']['db_user']
    tns_file = '/path/to/tnsnames.ora'
    env = config['oracle']['environment']
    db_pass = 'SuperSecretSring' # Do NOT store passwords in clear text in code.
    db_hosts = db_audit.get_db_list(tns_file, db_pass, env)
    # Getting a list of DB users.
    log.info('Beginning Oracle ITGC audit.')
    for db in db_hosts['active_dbs']:
        db_usernames = []
        user_info = db_audit.get_db_users(db_pass, db)
        for entry in user_info:
            if (entry['profile'] != 'SCHEMA_PROF' and
                    entry['profile'] != 'DEFAULT'):
                db_usernames.append(entry['username'])
```  
**get_db_granted_roles**(pwd, db_host)  

Keyword Arguments:  
- pwd \- A string that reprsents the password that will be used to connect to the datbase.
- db_host \- A string that is the Oracle DB's SID.

Returns:  
- db_granted_roles \- A list of database user dictionaries containg the granted role(s) of each user.  

Raises:  
- Error \- The base class for exceptions for the cx_oracle module.  This occurs when anything goes wrong connecting to the the target DB.  The base class is used in order to be able to catch any sub-exception, the details of which would be logged.

Code Example:  
```python
    from lib import itgcbin


    db_audit = itgcbin.OracleDBAudit()
    # Retrieving data from the config.
    db_audit.db_user = config['oracle']['db_user']
    tns_file = '/path/to/tnsnames.ora'
    env = config['oracle']['environment']
    db_pass = 'SuperSecretSring' # Do NOT store passwords in clear text in code.
    db_hosts = db_audit.get_db_list(tns_file, db_pass, env)
    log.info('Beginning Oracle ITGC audit.')
    for db in db_hosts['active_dbs']:
        # Getting granted roles.
        granted_roles = db_audit.get_db_granted_roles(db_pass, db)
        for role in granted_roles:
                if (role['granted_role'] == 'DBA'):
                    db_admins.append(role['username'])
```

**get_db_list**(t_file, db_pwd, env)

Keyword Arguments:  
- _file \- A string that should be the location of the tnsnames.ora file.
- db_pwd \- A string that should be the corresponding password for the self.db_user.
- env \- A string that should bet he environment to audit (i.e., production or non-production).

Returns:  
- host_lost \- A dictionary containing a list of reachable DBs and a list of unreachable DBs.

Raises:  
- Error \- The base class for exceptions for the cx_oracle module.  This occurs when anything goes wrong connecting to the the target DB.  The base class is used in order to be able to catch any sub-exception, the details of which would be logged.  If an exception occurs attempting to connecing to the DB, that DB is added to a list of unreachable DBs.

Code Example:
```python
    from lib import itgcbin


    db_audit = itgcbin.OracleDBAudit()
    # Getting information from the config.
    db_audit.db_user = config['oracle']['db_user']
    env = config['oracle']['environment']
    tns_file = '/path_to_tnsnames.ora'
    db_pass = 'ClearTextPasswordAreEvil' # Never, ever do this.
    db_hosts = db_audit.get_db_list(tns_file, db_pass, env)
    # Counting the DBs.
    alive_int = len(db_hosts['active_dbs'])
    dead_int = len(db_hosts['dead_dbs'])
    total_int = alive_int + dead_int
    # Printing all the active DBs.  We would normally run audits
    # against these.
    for active_db in db_hosts['active_dbs']:
        print('%s is an active DB.', active_db)
    # Printing unreachable DBs.  Troubleshoot these.
    for dead_db in db_hosts['dead_dbs']:
        print('%s is not an active DB.', dead_db)  
```

**get_admin_ex**(known_admins, db_admins)

Keyword Arguments:  
- known_admins \- A list of known admins who are approved to have admin level privileges.
- db_admins \- Users with an admin role that are retrieved from the Oracle DB.

Returns:  
- admin_ex \- A list of DB users that are not approved having an admin role.  

Code Example:  
```python
    from lib import itgcbin


    db_audit = itgcbin.OracleDBAudit()
    # Retrieving data from the config.
    db_audit.db_user = config['oracle']['db_user']
    tns_file = '/path/to/tnsnames.ora'
    env = config['oracle']['environment']
    db_pass = 'SuperSecretSring' # Do NOT store passwords in clear text in code.
    db_hosts = db_audit.get_db_list(tns_file, db_pass, env)
    log.info('Beginning Oracle ITGC audit.')
    for db in db_hosts['active_dbs']:
        # Getting granted roles.
        granted_roles = db_audit.get_db_granted_roles(db_pass, db)
        # Creating an admin list.
        for role in granted_roles:
                if (role['granted_role'] == 'DBA'):
                    db_admins.append(role['username'])
        # Checking for DBA exceptions.
        dba_exception = db_audit.get_admin_ex(
            config['oracle']['known_admins'], db_admins
        )
        print('Here are the bad admins:', dba_exception)
```

**get_bad_profiles**(db_users)

Keyword Arguments:  
- db_users \- A list of DB users and profiles generated by the get_db_users method.

Returns:  
- bad_profiles \- A dictionary containg two lists: a list of human users with SCHEMA_PROF (bad_profiles['schema_prof']) and a list of all users with the DEFAULT profile (bad_profiles['default_prof']).  

Code Example:  
```python
    from lib import itgcbin


    db_audit = itgcbin.OracleDBAudit()
    # Retrieving data from the config.
    db_audit.db_user = config['oracle']['db_user']
    tns_file = '/path/to/tnsnames.ora'
    env = config['oracle']['environment']
    db_pass = 'SuperSecretSring' # Do NOT store passwords in clear text in code.
    db_hosts = db_audit.get_db_list(tns_file, db_pass, env)
    log.info('Beginning Oracle ITGC audit.')
    for db in db_hosts['active_dbs']:
        # Getting user list.
        user_info = db_audit.get_db_users(db_pass, db)
        # Getting bad profiles.
        bad_profiles = db_audit.get_bad_profiles(user_info)
        print('Users with SCHEMA_PROF:', bad_profiles['schema_prof'])
        print('Users with DEAFULT:', bad_profiles['default_prof'])
```

<h2>UnixHostAudit</h2>  
The UnixHostAudit class is a sub-class of the ITGCAudit class.  The UnixHostAudit class is designed to automate the user security review of Linux or AIX hosts.  This is accompslished by remotely executing commands on target hosts using SSH via the Paramiko module.  Additional methods can be added with minimal effort to perform additional auditing tasks as may be required.

**Class Methods**  
- **UnixHostAudit.get_users** \- Connects to a remote host via paramiko and generates a list of local users with the contents of /etc/passwd.  
- **UnixHostAudit.get_groups** \- Connect to a remote host via paramiko and generates a list of users in specific groups by obtaining the membership of specific groups in /etc/group.
- **UnixHostAudit.get_hosts** \- Connects to an OSSEC server and gathers a list of auditable hosts based on OS (AIX or Linux).  This method can be modified to use different sources if need be.  The reason that the list of OSSEC agents was used in this environment is that every *nix host has an OSSEC agent installed as part of the build process.  Therefore, it is a simple matter to obtain a complete list of *nix hosts.
- **UnixHostAudit.get_admin_ex** \- Compares the local admins (members of specific groups designated as admin groups, i.e., those who can run sudo commands of note) against a list of known admins.  Returns the difference, which would be a list of accounts that are not authorized to have admin privileges.  This is essentially an over-glorified list comparison.  
- **UnixHostAudit.get_pwd_exp_exceptions** \- Returns a list of local "service" accounts who have not changed their password in 365 days.  Service accounts, in this context, are accounts that have a valid shell but are not in Active Directory (an example would be root).  These accounts should not be utilized by humans except in very specific circumstances or in the event of an emergency (break glass to keep the system up kind of thing).

**Class Variables**
- **UnixHostAudit.os** - The operating system (AIX or Linux) that is going to be audited.  This must be passed during class instantiation.  This will be used to determine which OSSEC agents to capture as a host list.  

<h3>UnixHostAudit Method Documentation</h3>

**get_users**(host)

Keyword Arguments:  
- host \- The remote host to perform security testing against.  

Returns:  
- local_users \- A list object containing users in /etc/passwd that have a valid shell that would allow them to log in and be able to interact with the system.

Raises:  
- AuthenticationException \- Paramiko exception that occurs when there is a problem authenticating to the remote host with the provided credentials (i.e. bad password or key)  
- SSHException \- Paramiko exception that occurs when there is an underlying problem making the SSH connection that is not a timeout error or authentication.  
- timeout \- When the SSH connection fails due to a timeout.

Code Example:
```python
    from lib import itgcbin


    LinuxAudit = itgcbin.UnixHostAudit('Linux')
    # Getting host list from OSSEC server.
    ossec_server = hostname.example.com
    linux_host_list = LinuxAudit.get_hosts(ossec_server)
    # Getting user list from remote host.
    for host in linux_host_list.get('active_hosts'):
        users = LinuxAudit.get_users(host)
        print('The users for %s are:%s' % (host, str(users).strip('[]'))
```  
**get_groups**(host, monitored_groups)

Keyword Arugments:  
- host \- The remote host to perform security testing against. 
- monitored groups \- A list containing the admin groups to monitor.  

Returns:
- audited_grops \- The groups to perform membership audits against.

Raises:
- AuthenticationException \- Paramiko exception that occurs when there is a problem with the  credentials used for SSH authentication.
- SSHException \- Paramkio exception that occurs when there is an underlying problem making the SSH connection that is not a timeout error or authentication.
- timeout \- Occurs when the SSH connection fails due to a timeout.

Code Example:  
```python
    from lib import itgcbin


    LinuxAudit = itgcbin.UnixHostAudit('Linux')
    # Getting host list from OSSEC server.
    ossec_server = hostname.example.com
    linux_host_list = LinuxAudit.get_hosts(ossec_server)
    # Geting groups to audit from config.
    monitored_groups = config['linux']['admin_groups'].split(',')
    # Generating known admin list.
    known_admins = []
    admin_file = open(
        config['linux']['known_admins'], 'r', encoding='ascii'
        )
    for admin_group in admin_file:
        known_admins.append(admin_group)
    # Performing audit.
    for host in linux_host_list.get('active_hosts'):
        admin_groups = LinuxAudit.get_groups(host, monitored_groups)
        bad_admins = LinuxAudit.get_admin_ex(known_admins, admin_groups)
        print('The bad admins on %s are %s' % (host, bad_admins.strip('[]')))
```
**get_hosts**(ossec_server)

Keyword Arguments:
- ossec_server \- The ossec server to retrieve a list of agents from.

Returns:
- audited_hosts \- The list of hosts to audit.

Raises:
- AuthenticationException \- Paramiko exception that occurs when there is a problem with the  credentials used for SSH authentication.
- SSHException \- Paramkio exception that occurs when there is an underlying problem making the SSH connection that is not a timeout error or authentication.

Code Example:
```python
    from lib import itgcbin

    
    LinuxAudit = itgcbin.UnixHostAudit('Linux')
    ossec_server = hostname.example.com
    # Getting Linux hosts
    linux_host_list = LinuxAudit.get_hosts(ossec_server)
    AIXAudit = itgcbin.UnixHostAudit('AIX')
    # Getting AIX hosts
    aix_host_list = AIXAudit.get_hosts(ossec_server)
    for linux_host in linux_host_list:
        print('%s is a Linux host', linux_host)
    for aix_host in aix_host_list:
        print('%s is an AIX host', aix_host)
```  
**get_admin_ex**(known_admins, host_admins)

Keyword Arguments:  
- known_admins \- This is a list of admins that are are obtained from the configuration file specified in self.conf (an attribute inherited from the ITGCAudit class).  The specific place in the configuration would be config['linux']['known_admins'].  This is a file that contains all of the apporpriate administrators (one per line).
- host_admins \- This is a list of admin group members from the audited host that is retrieved by the **get_groups** method.

Returns:
- admin_ex \- A list of accounts that are in a designated admin group that are not in the list of approved admins.  Each group's exceptions are identified as a dictionary (e,g. {'sudo': 'bad_admin1', 'bad_admin2'}).  Ideally, this should be an empty list.  

Code Example:
```python
    from lib import itgcbin


    LinuxAudit = itgcbin.UnixHostAudit('Linux')
    # Getting host list from OSSEC server.
    ossec_server = hostname.example.com
    linux_host_list = LinuxAudit.get_hosts(ossec_server)
    # Geting groups to audit from config.
    monitored_groups = config['linux']['admin_groups'].split(',')
    # Generating known admin list.
    known_admins = []
    admin_file = open(
        config['linux']['known_admins'], 'r', encoding='ascii'
        )
    for admin_group in admin_file:
        known_admins.append(admin_group)
    # Performing audit.
    for host in linux_host_list.get('active_hosts'):
        admin_groups = LinuxAudit.get_groups(host, monitored_groups)
        bad_admins = LinuxAudit.get_admin_ex(known_admins, admin_groups)
        print('The bad admins on %s are %s' % (host, bad_admins))
```  
**get_pwd_exp_exceptions**(host, local_users, ad_users)  

Keyword Arguments:  
- host \- The remote host to audit.
- local_users \- The local users from the remote host.  These are obtained by the **get_users** method.
- ad_users \- A list of users from Active Directory.  These are obtained by the **get_ad_users** method inherited from the ITGCAudit class.

Returns:
- audit_exceptions \- The list of service accounts that have a password that has not been changed in the past 365 days.  This value is set in the config['linux']['pwd_rotate'] portion of the configuration.

Raises:
- AuthenticationException \- Paramiko exception that occurs when there is a problem with the provided credentials.
- SSHException \- An underlying problem making the SSH connection that is not a timeout error or authentication.
- timeout \- When the SSH connect fails due to a timeout.
- ValueError \- Occurs when input validation fails.  

Code Example:  
```python
    from lib import itgcbin


    LinuxAudit = itgcbin.UnixHostAudit('Linux')
    ossec_server = 'hostname.example.com'
    # Getting a list of Linux hosts to audit.
    linux_hosts = LinuxAudit.get_hosts(ossec_server)
    # Getting a list of AD users.
    ad_users = LinuxAudit.get_ad_users()
    for linux_host in linux_hosts:
        # Getting local users
        local_users = LinuxAudit.get_users(linux_host)
        # Auditing local service account password expiration.
        expired_svc_accounts = LinuxAudit.get_pwd_exp_exceptions(
            linux_host,
            local_users,
            ad_users
        )
        print(
            'The following service accounts have old passwords: %s',
            expired_svc_accounts
        )
```