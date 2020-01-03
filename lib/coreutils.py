#!/usr/bin/python3
from socket import gethostbyname, gaierror
from smtplib import SMTP, SMTPConnectError
from email.mime.text import MIMEText

from requests import post
from paramiko import SSHClient, AuthenticationException
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
    scss_response = post(url, headers=headers, verify=False)
    if scss_response.status_code == 200:
        data = scss_response.json().get('gpg_pass')
    else:
        exit(1)
    return data


def connect_test(host):
    """Returns true if connection is successful.

    Keyword Arguments:
    host - str(), the host's name.

    Outputs.
    Bool."""
    client = SSHClient()
    client.load_system_host_keys()
    try:
        if client.connect(host):
            return True
        else:
            return False
    except AuthenticationException:
        return False
