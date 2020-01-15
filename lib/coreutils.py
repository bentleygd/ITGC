#!/usr/bin/python3
from socket import gethostbyname, gaierror
from smtplib import SMTP, SMTPConnectError
from email.mime.text import MIMEText
from socket import timeout
from logging import getLogger

from requests import post
from paramiko import SSHClient, WarningPolicy
from paramiko.ssh_exception import (
    NoValidConnectionsError, BadHostKeyException, AuthenticationException,
    SSHException
)
from pyotp import TOTP


def mail_send(mail_info):
    """Takes input, sends mail.

    Keyword arguments:
    mail_info - A dict() object with the following keys and
    corresponding values: sender, recipients, subject, server and
    body.

    Outputs:
    Sends an email, returns nothing.

    Raises:
    gaierror - Occurs when DNS resolution of a hostname fails.
    SMTPConnectError - Occurs when the remote SMTP sever refuses the
    connection."""
    # Defining mail properties.
    msg = MIMEText(mail_info['body'])
    msg['Subject'] = mail_info['subject']
    msg['From'] = mail_info['sender']
    msg['To'] = mail_info['recipients']
    # Obtaining IP address of SMTP server host name.  If using an IP
    # address, omit the gethostbyname function.
    try:
        s = SMTP(gethostbyname(mail_info['server']), '25')
    except gaierror:
        print('Hostname resolution of %s failed.' % mail_info['server'])
        exit(1)
    except SMTPConnectError:
        print('Unable to connect to %s, the server refused the ' +
              'connection.' % mail_info['server'])
        exit(1)
    # Sending the mail.
    s.sendmail(mail_info['sender'], mail_info['recipients'], msg.as_string())


def get_credentials(scss_dict):
    """Makes an API call to SCSS, returns credentials.

    Keyword Arguments:
    scss_dict - a dict() object containing the following keys with
    the correct corresponding values: api_key, otp, userid and url.

    Output:
    data - str(), the data returned from scss."""
    log = getLogger('ITGC_Audit')
    api_key = scss_dict['api_key']
    otp = TOTP(scss_dict['otp']).now()
    userid = scss_dict['userid']
    url = scss_dict['url']
    user_agent = 'scss-client'
    headers = {
        'User-Agent': user_agent,
        'api-key': api_key,
        'totp': otp,
        'userid': userid
    }
    scss_response = post(url, headers=headers,
                         verify='/etc/pki/tls/certs/ca-bundle.crt')
    if scss_response.status_code == 200:
        data = scss_response.json().get('gpg_pass')
        log.debug('Credentials successfully retrieved from SCSS')
    else:
        log.error('Unable to retrieve credentials from SCSS.  The HTTP '
                  'error code is %s', scss_response.status_code)
        exit(1)
    return data


def ssh_test(host):
    """Returns true if connection is successful.

    Keyword Arguments:
    host - str(), the host's name.

    Outputs:
    True or False based on whether or not the function generates an
    exception.

    Raises:
    BadHostKeyException - The host key given by the SSH server did not
    match what we were expecting.
    AuthenticatoinException - Authentication failed for some reason.
    SSHException - Failures in SSH2 protocol negotiation or logic
    errors.
    timeout - Timeout occurs after 5 seconds.
    gaierror - DNS resolution failure."""
    log = getLogger('ITGC_Audit')
    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(WarningPolicy)
    try:
        client.connect(host, timeout=5, auth_timeout=5)
        client.close()
        return True
    except BadHostKeyException:
        log.exception('Bad host key for %s', host)
        return False
    except AuthenticationException:
        log.exception('Authentication faield for %s', host)
        return False
    except NoValidConnectionsError:
        log.exception('No valid connections for %s', host)
        return False
    except SSHException:
        log.exception('Generic SSH exception noted for %s', host)
        return False
    except timeout:
        log.exception('Timeout occurred when connecting to %s', host)
        return False
    except gaierror:
        log.exception('DNS resolution failed for %s', host)
        return False
