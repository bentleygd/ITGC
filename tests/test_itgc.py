from configparser import ConfigParser
from os.path import exists

# from lib.coreutils import ssh_test
from lib.validate import validate_email, validate_hn
from lib import itgcbin


class TestBaseConfig:
    """Class for configuration testing.

    Keyword Arguments:
    None

    Instance Variables:
    None.

    Methods:
    does_config_exist - Tests to see if config exists.
    mail_config_test - Tests to see if config contains mail elements.
    ossec_test - Tests SSH connectivity to an ossec server."""

    def test_config_exist(self):
        """Returns true if config exists.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        test = exists('test.cnf')
        assert test is True

    def test_mail_config(self):
        """Returns true if mail configuration exists and is configured
        appropriately.

        Keyword Arugments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        test_results = {
            'base_section': str(), 'sender': str(),
            'recipient': str(), 'server': str()
        }
        if 'mail' in config:
            test_results['base_section'] = 'yes'
        else:
            test_results['base_section'] = 'no'

        if 'sender' in config['mail']:
            if validate_email(config['mail']['sender']):
                test_results['sender'] = 'yes'
            else:
                test_results['sender'] = 'no'
        else:
            test_results['sender'] = 'no'

        if 'recipient' in config['mail']:
            if ',' in config['mail']['recipient']:
                emails = config['mail']['recipient'].split(',')
                for email in emails:
                    if validate_email(email):
                        test_results['recipient'] = 'yes'
                    else:
                        test_results['recipient'] = 'no'
            else:
                if validate_email(config['mail']['recipient']):
                    test_results['recipient'] = 'yes'
                else:
                    test_results['recipient'] = 'no'
        else:
            test_results['recipient'] = 'no'

        if 'server' in config['mail']:
            if validate_hn(config['mail']['server']):
                test_results['server'] = 'yes'
            else:
                test_results['server'] = 'no'
        else:
            test_results['server'] = 'no'

        if 'no' in test_results:
            test = False
        else:
            test = True
        assert test is True


class TestLinuxConfig:
    """Class for Linux Audtiing configuration testing.

    Keyword Arguments:
    None

    Instance Variables:
    None

    Methods:
    test_config_exist - Tests to see if config exists.
    test_linux_config_test - Tests to see if config contains Linux
    elements.
    test_linux_admin_groups - Tests to see if config contains admin
    group elements.
    test_linux_exclusions - Tests to see if config contains exclusion
    elements."""

    def test_config_exist(self):
        """Returns true if config file exists.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        test = exists('test.cnf')
        assert test is True

    def test_linux_config_exist(self):
        """Returns true if Linux configuration elements exist.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'linux' in config:
            test = True
        else:
            test = False
        assert test is True

    def test_linux_admin_groups(self):
        """Returns true if the configuration file contains the admin
        group element specific to Linux servers and the configuration
        element contains an appropriate number of admins.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'admin_groups' in config['linux']:
            # Change the number as appropriate.
            linux_admins = config['linux']['admin_groups'].split(',')
            if len(linux_admins) > 3:
                test = True
            else:
                test = False
        else:
            test = False
        assert test is True

    def test_linux_exclusions(self):
        """Returns true if the configuration file contains the
        exclusions element specific to Linux servers.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'exclusions' in config['linux']:
            test = True
        else:
            test = False
        assert test is True

    def test_linux_known_admins(self):
        """Returns true if the configuration file contains the known
        admins element specific to Linux servers and the known admin
        file exists.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'known_admins' in config['linux']:
            if exists(config['linux']['known_admins']):
                test = True
            else:
                test = False
        else:
            test = False
        assert test is True


class TestAIXConfig:
    """Class for AIX Audtiing configuration testing.

    Keyword Arguments:
    None

    Instance Variables:
    None

    Methods:
    test_config_exist - Tests to see if config exists.
    test_aix_config_test - Tests to see if config contains AIX
    elements.
    test_aix_admin_groups - Tests to see if config contains admin
    group elements.
    test_aix_exclusions - Tests to see if config contains exclusion
    elements."""

    def test_config_exist(self):
        """Returns true if config file exists.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        test = exists('test.cnf')
        assert test is True

    def test_aix_config_exist(self):
        """Returns true if AIX configuration elements exist.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'aix' in config:
            test = True
        else:
            test = False
        assert test is True

    def test_aix_admin_groups(self):
        """Returns true if the configuration file contains the admin
        group element specific to AIX servers and the configuration
        element contains an appropriate number of admins.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'admin_groups' in config['aix']:
            # Change the number as appropriate.
            aix_admins = config['aix']['admin_groups'].split(',')
            if len(aix_admins) > 3:
                test = True
            else:
                test = False
        else:
            test = False
        assert test is True

    def test_aix_exclusions(self):
        """Returns true if the configuration file contains the
        exclusions element specific to AIX servers.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'exclusions' in config['aix']:
            test = True
        else:
            test = False
        assert test is True

    def test_aix_known_admins(self):
        """Returns true if the configuration file contains the known
        admins element specific to AIX servers and the known admin
        file exists.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'known_admins' in config['aix']:
            if exists(config['aix']['known_admins']):
                test = True
            else:
                test = False
        else:
            test = False
        assert test is True


class TestOracleConfig:
    """Class for AIX Audtiing configuration testing.

    Keyword Arguments:
    None

    Instance Variables:
    None

    Methods:
    test_config_exist - Tests to see if config exists.
    test_oracle_config - Tests to see if config contains Oracle
    elements.
    test_dba_members - Tests to see if config contains known good dbas.
    test_oracle_exclusions - Tests to see if config contains exclusion
    elements."""

    def test_config_exist(self):
        """Returns true if config file exists.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        test = exists('test.cnf')
        assert test is True

    def test_oracle_config(self):
        """Returns true if oracle configuration elements exist.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'oracle' in config:
            test = True
        else:
            test = False
        assert test is True

    def test_dba_members(self):
        """Returns true if the configuration file contains an element
        that contains known good DBAs.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'known_admins' in config['oracle']:
            # Change the number as appropriate.
            dbas = config['oracle']['known_admins'].split(',')
            if len(dbas) > 3:
                test = True
            else:
                test = False
        else:
            test = False
        assert test is True

    def test_oracle_exclusions(self):
        """Returns true if the configuration file contains the
        exclusions element specific to Oracle DBs.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raises:
        None."""
        config = ConfigParser()
        config.read('test.cnf')
        if 'exclusions' in config['oracle']:
            test = True
        else:
            test = False
        assert test is True


class TestITGCCode:
    """Class for ITGC code testing.

    Keyword Arguments:
    None

    Instance Variables:
    None

    Methods:
    test_config_exist - Tests to see if config exists.
    test_oracle_config - Tests to see if config contains Oracle
    elements.
    test_dba_members - Tests to see if config contains known good dbas.
    test_oracle_exclusions - Tests to see if config contains exclusion
    elements."""

    def test_audit_ex(self):
        """Tests audit exception code.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raies:
        None."""
        ad_users = ['frodo', 'bilbo', 'gandalf', 'galadriel']
        local_users = ['gollum', 'samwise', 'gandalf', 'galadriel', 'frodo']
        exclusions = ['samwise']
        test_audit = itgcbin.ITGCAudit()
        test = test_audit.get_audit_ex(local_users, ad_users, exclusions)
        assert 'gollum' in test

    def test_dba_ex(self):
        """Tests dba exception code.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raies:
        None."""
        good_dbas = ['tstark', 'hstark', 'bbanner', 'sstrange']
        local_dbas = ['tstark', 'bmordo', 'sstrange', 'nosborn']
        test_audit = itgcbin.OracleDBAudit()
        test = test_audit.get_admin_ex(good_dbas, local_dbas)
        assert 'nosborn' and 'bmordo' in test

    def test_nix_audit_ex(self):
        """Tests dba exception code.

        Keyword Arguments:
        None.

        Outputs:
        True or False.

        Raies:
        None."""
        known_admin = ['sudo: yoda, mwindu, kadimundi, pkloon, sti, okenobi']
        audit_admins = [{'sudo': ['yoda', 'askywalker', 'asecura', 'sti']}]
        test_audit = itgcbin.UnixHostAudit('Linux')
        test = test_audit.get_admin_ex(known_admin, audit_admins)
        assert 'askywalker' and 'asecura' in test[0]['sudo']
