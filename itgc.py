#!/usr/bin/python3
from csv import DictWriter, DictReader
from time import time
from argparse import ArgumentParser
from configparser import ConfigParser

from lib.coreutils import mail_send, get_credentials
from lib import itgcbin


def main():
    """Doing the thing."""
    # Setting up an argument parser.
    a_parse = ArgumentParser(description='SOX security reviews')
    a_parse.add_argument('os', type=str, help='Linux, AIX or Oracle')
    args = a_parse.parse_args()
    # Setting up the results file.
    results_write = open('audit_results.csv', 'w')
    fields = ['host_name', 'admin_exceptions', 'orphans']
    results = DictWriter(results_write, fieldnames=fields)
    results.writeheader()
    # Setting mail configuration.
    config = ConfigParser()
    config.read('test.cnf')
    sender = config['mail']['sender']
    recipient = config['mail']['recipient']
    smtp_server = config['mail']['server']
    # Getting audit info.
    ossec_server = config['main']['ossec']
    user = config['main']['audit_user']

    if args.os == 'Linux':
        LinuxAudit = itgcbin.UnixHostAudit('Linux')
        # Variable initialization
        monitored_groups = config['linux']['admin_groups'].split(',')
        exclusions = config['linux']['exclusions'].split(',')
        known_admins = []
        admin_file = open(
            config['linux']['known_admins'], 'r', encoding='ascii'
            )
        for admin_group in admin_file:
            known_admins.append(admin_group)
        start = time()
        linux_host_list = LinuxAudit.get_hosts(user, ossec_server)
        ad_users = LinuxAudit.get_ad_users(user, ossec_server)
        alive_int = len(linux_host_list.get('active_hosts'))
        dead_int = len(linux_host_list.get('dead_hosts'))
        total_int = alive_int + dead_int
        # Running the audit for Linux.
        for host in linux_host_list.get('active_hosts'):
            users = LinuxAudit.get_users(host)
            admin_groups = LinuxAudit.get_groups(host, monitored_groups)
            if len(users) < 1:
                orphans = ['Unable to retrieve users.']
            else:
                orphans = str(LinuxAudit.get_audit_ex(
                    users, ad_users, exclusions
                    ))
            bad_admins = LinuxAudit.get_admin_ex(
                known_admins, admin_groups
            )
            results.writerow(
                {'host_name': host, 'admin_exceptions': bad_admins,
                 'orphans': orphans}
            )
        results_write.close()
        # Parsing the results of the audit.
        results_read = open('audit_results.csv', 'r', newline='')
        r_reader = DictReader(results_read)
        msg_body = '%d hosts were succsefully audited out of %d hosts\n\n' % (
            alive_int, total_int
        )
        for row in r_reader:
            msg_body = msg_body + (
                '*' * 64 + '\n' +
                '%s results:\n' % row['host_name']
            )
            msg_body = msg_body + 'Accounts without AD account: '
            for orphan in list(row['orphans']):
                msg_body = msg_body + orphan
            msg_body = msg_body + '\n'
            msg_body = msg_body + 'Admin Exceptions: '
            for exception in list(row['admin_exceptions']):
                msg_body = msg_body + exception
            msg_body = msg_body + '\n\n'
        msg_body = msg_body + (
            '*' * 64 + '\n' +
            'Active Hosts: %s\n' % (linux_host_list.get('active_hosts')) +
            '*' * 64 + '\n' +
            'Unreachlable Hosts: %s\n' % (linux_host_list.get('dead_hosts'))
        )
        end = time()
        diff = round(end - start, 2)
        msg_body = msg_body + (
            'Script execution time: %d seconds\n' % diff
        )
        # Emailing a report with the audit findings.
        mail_send(sender, recipient, 'SOX Monthly Linux Security Review ' +
                  'Report', smtp_server, msg_body)
        results_read.close()

    if args.os == 'AIX':
        AIXAudit = itgcbin.UnixHostAudit('AIX')
        # Variable initilization
        monitored_groups = config['aix']['admin_groups'].split(',')
        exclusions = config['aix']['exclusions'].split(',')
        known_admins = []
        admin_file = open(
            config['aix']['known_admins'], 'r', encoding='ascii'
            )
        for admin_group in admin_file:
            known_admins.append(admin_group)
        aix_known_hosts = config['aix']['known_hosts'].split(',')
        start = time()
        aix_host_list = AIXAudit.get_hosts(user, ossec_server)
        for aix_host in aix_known_hosts:
            if aix_host not in aix_host_list['active_hosts']:
                aix_host_list['active_hosts'].append(aix_host)
        ad_users = AIXAudit.get_ad_users(user, ossec_server)
        alive_int = len(aix_host_list.get('active_hosts'))
        dead_int = len(aix_host_list.get('dead_hosts'))
        total_int = alive_int + dead_int
        # Running the audit for AIX.
        for host in aix_host_list.get('active_hosts'):
            users = AIXAudit.get_users(host)
            admin_groups = AIXAudit.get_groups(host, monitored_groups)
            if len(users) < 1:
                orphans = ['Unable to retrieve users.']
            else:
                orphans = str(AIXAudit.get_audit_ex(
                    users, ad_users, exclusions
                    ))
            bad_admins = AIXAudit.get_admin_ex(
                known_admins, admin_groups
            )
            results.writerow(
                {'host_name': host, 'admin_exceptions': bad_admins,
                 'orphans': orphans}
            )
        results_write.close()
        # Parsing the results of the audit.
        results_read = open('audit_results.csv', 'r', newline='')
        r_reader = DictReader(results_read)
        msg_body = '%d hosts were succsefully audited out of %d hosts\n\n' % (
            alive_int, total_int
        )
        for row in r_reader:
            msg_body = msg_body + (
                '*' * 64 + '\n' +
                '%s results:\n' % row['host_name']
            )
            msg_body = msg_body + 'Accounts without AD account: '
            for orphan in list(row['orphans']):
                msg_body = msg_body + orphan
            msg_body = msg_body + '\n'
            msg_body = msg_body + 'Admin Exceptions: '
            for exception in list(row['admin_exceptions']):
                msg_body = msg_body + exception
            msg_body = msg_body + '\n\n'
        msg_body = msg_body + (
            '*' * 64 + '\n' +
            'Active Hosts: %s\n' % (aix_host_list.get('active_hosts')) +
            '*' * 64 + '\n' +
            'Unreachlable Hosts: %s\n' % (aix_host_list.get('dead_hosts'))
        )
        end = time()
        diff = round(end - start, 2)
        msg_body = msg_body + (
            'Script execution time: %d seconds\n' % diff
        )
        # Emailing a report with the audit findings.
        mail_send(sender, recipient, 'SOX Monthly AIX Security Review Report',
                  smtp_server, msg_body)
        results_read.close()

    if args.os == 'Oracle':
        # Setting up the results file.
        results_write = open('audit_results.csv', 'w')
        fields = ['db_name', 'dba_exceptions', 'orphans', 'bad_profiles']
        results = DictWriter(results_write, fieldnames=fields)
        results.writeheader()
        # Object instantiation
        db_audit = itgcbin.OracleDBAudit()
        # Variable initialization
        db_list = []
        db_usernames = []
        db_admins = []
        db_audit.db_user = config['oracle']['db_user']
        scss_dict = {
            'api_key': config['oracle']['scss_api'],
            'otp': config['oracle']['scss_otp'],
            'userid': config['oracle']['scss_user'],
            'url': config['oracle']['scss_url']
        }
        tns_file = '/opt/oracle/instantclient_11_2/network/admin/tnsnames.ora'
        db_pass = get_credentials(scss_dict)
        db_hosts = db_audit.get_db_list(tns_file, db_pass)
        ad_users = db_audit.get_ad_users(
            config['ossec']['audit_user'], config['ossec']['ossec']
        )
        # Creating a list of DBs applicable to the environment.
        if config['oracle']['environment'] == 'NPRD':
            for host in db_hosts:
                if 'QA' in host or 'DEV' in host:
                    db_list.append(host)
        elif config['oracle']['environment'] == 'PRD':
            for host in db_hosts:
                if 'QA' not in host and 'DEV' not in host:
                    db_list.append(host)
        # Running the audit.
        for db in db_list:
            user_info = db_audit.get_db_users(db_pass, db)
            for entry in user_info:
                if (entry['profile'] != 'SCHEMA_PROF' or
                        entry['profile'] != 'DEFAULT'):
                    db_usernames.append(entry['username'])
            # Checking for users past term.
            audit_ex = db_audit.get_audit_ex(
                db_usernames, ad_users, config['oracle']['exclusions']
            )
            # Checking for misconfigured profiles.
            bad_profiles = db_audit.get_bad_profiles(user_info)
            granted_roles = db_audit.get_db_granted_roles(db_pass, db)
            for role in granted_roles:
                if (role['granted_role'] == 'DBA'):
                    db_admins.append(role['username'])
            # Checking for DBA exceptions.
            dba_exception = db_audit.get_admin_ex(
                config['oracle']['known_admins'], db_admins
            )
            results.writerow(
                {'db_name': db,
                 'dba_exceptions': dba_exception,
                 'orphans': audit_ex,
                 'bad_profiles': bad_profiles}
            )
        results_write.close()


if __name__ == '__main__':
    main()
