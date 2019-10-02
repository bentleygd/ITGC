#!/usr/bin/python3
from csv import DictWriter
# from coreutils import mailSend
import itgcbin


def main():
    """Doing the thing."""
    # Setting up the results file.
    results_file = open('audit_results.csv', 'w')
    fields = ['host_name', 'admin_exceptions', 'orphans']
    results = DictWriter(results_file, fieldnames=fields)
    results.writeheader()
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
            {'host_name':host, 'admin_exceptions': bad_admins,
             'orphans': orphans}
        )
    results_file.close()


if __name__ == '__main__':
    main()
