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
    admins_file = open('known_admins.list', 'r', encoding='ascii')
    kg_admins = [admins.strip('\n') for admins in admins_file]
    admin_exc = []
    # Running the info.
    host_list = itgcbin.getHosts(ossec_server)
    ad_users = itgcbin.getADUsers(ossec_server)
    for host in host_list:
        users = itgcbin.getUsers(host)
        admin_groups = itgcbin.getGroups(host)
        orphans = itgcbin.getOrphans(users, ad_users)
        # Placeholder


if __name__ == '__main__':
    main()
