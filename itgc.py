#!/usr/bin/python3
from csv import DictWriter, DictReader
from coreutils import mailSend, getConfig
import itgcbin


def main():
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
    host_list = itgcbin.getHosts(ossec_server)
    ad_users = itgcbin.getADUsers(ossec_server)
    alive_int = len(host_list.get('active_hosts'))
    dead_int = len(host_list.get('dead_hosts'))
    total_int = alive_int + dead_int
    # Running the audit.
    for host in host_list.get('active_hosts'):
        users = itgcbin.getUsers(host)
        admin_groups = itgcbin.getGroups(host)
        orphans = str(itgcbin.getOrphans(users, ad_users))
        bad_admins = itgcbin.getAdminEx('known_admins.list', admin_groups)
        results.writerow(
            {'host_name': host, 'admin_exceptions': bad_admins,
             'orphans': orphans}
        )
    results_write.close()
    results_read = open('audit_results.csv', 'r')
    r_reader = DictReader(results_read, fieldnames=fields, newline='')
    record_count = len(r_reader)
    msg_body = '%d hosts were succsefully audited out of %d hosts\n\n' % (
        alive_int, total_int
    )
    for row in r_reader[1:record_count]:
        msg_body = msg_body + (
            '*' * 32 + '\n' +
            '%s results:\nOrphans: %s\nAdmin Exceptions: %s\n' % (
                row['host_name'], row['orphans'], row['admin_exceptions']
            )
        )
    msg_body = msg_body + (
        'Alive Hosts:', host_list.get('active_hosts') + '\n' +
        'Dead Hosts:', host_list.get('dead_hosts') + '\n'
    )
    mailSend(sender, recipient, 'Monthly Security Review Report',
             smtp_server, msg_body)
    results_read.close()


if __name__ == '__main__':
    main()
