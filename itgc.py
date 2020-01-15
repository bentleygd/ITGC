#!/usr/bin/python3
from csv import DictWriter, DictReader
from time import time
from argparse import ArgumentParser
from configparser import ConfigParser
from logging import getLogger, basicConfig, INFO

from lib.coreutils import mail_send, get_credentials, ssh_test
from lib import itgcbin


def main():
    """Doing the thing."""
    # Setting up logging.
    log = getLogger('ITGC_Audit')
    basicConfig(
        format='%(asctime)s %(name)s %(levelname)s: %(message)s',
        datefmt='%m/%d/%Y %H:%M:%S',
        level=INFO,
        filename='itgc_audit.log'
    )
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
    mail_info = {
        'sender': str(), 'recipients': str(),
        'subject': str(), 'server': str(),
        'body': str()
    }
    mail_info['sender'] = config['mail']['sender']
    mail_info['recipients'] = config['mail']['recipient']
    mail_info['server'] = config['mail']['server']
    # Getting audit info.
    ossec_server = config['main']['ossec']

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
        linux_host_list = LinuxAudit.get_hosts(ossec_server)
        ad_users = LinuxAudit.get_ad_users(ossec_server)
        alive_int = len(linux_host_list.get('active_hosts'))
        dead_int = len(linux_host_list.get('dead_hosts'))
        total_int = alive_int + dead_int
        log.info('Beginning Linux ITGC Audit.')
        start = time()
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
            'Audit execution time: %d seconds\n' % diff
        )
        mail_info['body'] = msg_body
        mail_info['subject'] = 'SOX Monthly Linux Security Review Report'
        # Emailing a report with the audit findings.
        mail_send(mail_info)
        results_read.close()
        log.info('Linux audit completed in %d seconds', diff)

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
        aix_host_list = AIXAudit.get_hosts(ossec_server)
        for aix_host in aix_known_hosts:
            if (aix_host not in aix_host_list['active_hosts'] and
                    ssh_test(aix_host)):
                aix_host_list['active_hosts'].append(aix_host)
            else:
                aix_host_list['dead_hosts'].append(aix_host)
        ad_users = AIXAudit.get_ad_users(ossec_server)
        alive_int = len(aix_host_list.get('active_hosts'))
        dead_int = len(aix_host_list.get('dead_hosts'))
        total_int = alive_int + dead_int
        log.info('Beginning AIX ITGC audit.')
        start = time()
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
            'Audit execution time: %d seconds\n' % diff
        )
        mail_info['body'] = msg_body
        mail_info['subject'] = 'SOX Monthly AIX Security Review Report'
        # Emailing a report with the audit findings.
        mail_send(mail_info)
        results_read.close()
        log.info('AIX ITGC audit complete in %d seconds', diff)

    if args.os == 'Oracle':
        # Setting up the results file.
        results_write = open('audit_results.csv', 'w')
        fields = ['db_name', 'dba_exceptions', 'orphans',
                  'schema_prof', 'default_prof']
        results = DictWriter(results_write, fieldnames=fields)
        results.writeheader()
        # Object instantiation
        db_audit = itgcbin.OracleDBAudit()
        # Variable initialization
        db_audit.db_user = config['oracle']['db_user']
        scss_dict = {
            'api_key': config['oracle']['scss_api'],
            'otp': config['oracle']['scss_otp'],
            'userid': config['oracle']['scss_user'],
            'url': config['oracle']['scss_url']
        }
        tns_file = '/opt/oracle/instantclient_11_2/network/admin/tnsnames.ora'
        env = config['oracle']['environment']
        db_pass = get_credentials(scss_dict)
        db_hosts = db_audit.get_db_list(tns_file, db_pass, env)
        ad_users = db_audit.get_ad_users(ossec_server)
        # Creating a list of DBs applicable to the environment.
        alive_int = len(db_hosts['active_dbs'])
        dead_int = len(db_hosts['dead_dbs'])
        total_int = alive_int + dead_int
        # Running the audit.
        log.info('Beginning Oracle ITGC audit.')
        start = time()
        for db in db_hosts['active_dbs']:
            db_usernames = []
            db_admins = []
            user_info = db_audit.get_db_users(db_pass, db)
            for entry in user_info:
                if (entry['profile'] != 'SCHEMA_PROF' and
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
            # Writing to the results file.
            results.writerow(
                {'db_name': db,
                 'dba_exceptions': dba_exception,
                 'orphans': audit_ex,
                 'schema_prof': bad_profiles['schema_prof'],
                 'default_prof': bad_profiles['default_prof']}
            )
        results_write.close()
        # Parsing the results of the audit.
        results_read = open('audit_results.csv', 'r', newline='')
        r_reader = DictReader(results_read)
        msg_body = '%d hosts were successfully audited out of %d hosts\n\n' % (
            alive_int, total_int
        )
        for row in r_reader:
            msg_body = msg_body + (
                '*' * 64 + '\n' +
                '%s results:\n' % row['db_name']
            )
            msg_body = msg_body + 'Accounts without AD account: '
            for orphan in list(row['orphans']):
                msg_body = msg_body + orphan
            msg_body = msg_body + '\n'
            msg_body = msg_body + 'Admin Exceptions: '
            for exception in list(row['dba_exceptions']):
                msg_body = msg_body + exception
            msg_body = msg_body + '\n'
            msg_body = msg_body + 'Human users with Schema Profile: '
            msg_body = msg_body + row['schema_prof']
            msg_body = msg_body + '\n'
            msg_body = msg_body + 'Users with Default Profile: '
            msg_body = msg_body + row['default_prof']
            msg_body = msg_body + '\n\n'
        msg_body = msg_body + (
            '*' * 64 + '\n' +
            'Active DBs: %s\n' % (db_audit.host_list.get('active_dbs')) +
            '*' * 64 + '\n' +
            'Unreachable DBs: %s\n' % (db_audit.host_list.get('dead_dbs'))
        )
        end = time()
        diff = round(end - start, 2)
        msg_body = msg_body + (
            'Audit execution time: %d seconds\n' % diff
        )
        mail_info['body'] = msg_body
        mail_info['subject'] = 'SOX Monthly Oracle DB Security Review Report'
        # Emailing a report with the audit findings.
        mail_send(mail_info)
        results_read.close()
        log.info('Oracle ITGC audit complete in %d seconds', diff)


if __name__ == '__main__':
    main()
