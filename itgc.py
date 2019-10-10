#!/usr/bin/python3
from csv import DictWriter, DictReader
from time import time
from argparse import ArgumentParser

from coreutils import mailSend, getConfig
import itgcbin


def main():
    # Setting up an argument parser.
    a_parse = ArgumentParser(description='SOX security reviews')
    a_parse.add_argument('os', type=str, help='Linux or AIX')
    args = a_parse.parse_args()
    """Doing the thing."""
    # Setting up the results file.
    results_write = open('audit_results.csv', 'w')
    fields = ['host_name', 'admin_exceptions', 'orphans']
    results = DictWriter(results_write, fieldnames=fields)
    results.writeheader()
    # Setting mail configuration.
    config = getConfig('config.cnf')
    sender = config.GetMailSender()
    recipient = config.GetReportRcpts()
    smtp_server = config.GetSMTPServer()
    # Getting audit info.
    ossec_server = open('ossec.cnf', 'r', encoding='ascii').read().strip('\n')

    if args.os == 'Linux':
        start = time()
        linux_host_list = itgcbin.getLinuxHosts(ossec_server)
        ad_users = itgcbin.getADUsers(ossec_server)
        alive_int = len(linux_host_list.get('active_hosts'))
        dead_int = len(linux_host_list.get('dead_hosts'))
        total_int = alive_int + dead_int
        # Running the audit for Linux.
        for host in linux_host_list.get('active_hosts'):
            users = itgcbin.getUsers(host)
            admin_groups = itgcbin.getGroups(host, 'monitored_groups.list')
            orphans = str(itgcbin.getOrphans(
                users, ad_users, 'exclusions.list'
                ))
            bad_admins = itgcbin.getAdminEx(
                'known_admins.list', admin_groups
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
            msg_body = msg_body + 'Accounts active past term: '
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
        mailSend(sender, recipient, 'SOX Monthly Linux Security Review Report',
                 smtp_server, msg_body)
        results_read.close()

    if args.os == 'AIX':
        start = time()
        aix_host_list = itgcbin.getAIXHosts(ossec_server)
        ad_users = itgcbin.getADUsers(ossec_server)
        alive_int = len(aix_host_list.get('active_hosts'))
        dead_int = len(aix_host_list.get('dead_hosts'))
        total_int = alive_int + dead_int
        # Running the audit for Linux.
        for host in aix_host_list.get('active_hosts'):
            users = itgcbin.getUsers(host)
            admin_groups = itgcbin.getGroups(host, 'aix_m_groups.list')
            orphans = str(itgcbin.getOrphans(
                users, ad_users, 'aix_ex.list'
                ))
            bad_admins = itgcbin.getAdminEx(
                'aix_admins.list', admin_groups
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
            msg_body = msg_body + 'Accounts active past term: '
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
        mailSend(sender, recipient, 'SOX Monthly AIX Security Review Report',
                 smtp_server, msg_body)
        results_read.close()


if __name__ == '__main__':
    main()
