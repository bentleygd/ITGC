#!/usr/bin/python3
from socket import gethostbyname, gaierror
from smtplib import SMTP, SMTPConnectError
from email.mime.text import MIMEText


def mail_send(mail_sender, mail_recipients, subject, mail_server, mail_body):
    """Takes input, sends mail.

    Keyword arguments:
    mail_sender - The from address.
    mail_recipients -  The to address.
    subject - The subject line of the email.
    mail_server - The FQDN of the SMTP server/relay.
    mail_body - The body of the mail message.

    Outputs:
    Sends an email, returns nothing.

    Raises:
    gaierror - Occurs when DNS resolution of a hostname fails.
    SMTPConnectError - Occurs when the remote SMTP sever refuses the
    connection.
    """
    # Defining mail properties.
    msg = MIMEText(mail_body)
    msg['Subject'] = subject
    msg['From'] = mail_sender
    msg['To'] = mail_recipients
    # Obtaining IP address of SMTP server host name.  If using an IP
    # address, omit the gethostbyname function.
    try:
        s = SMTP(gethostbyname(mail_server), '25')
    except gaierror:
        print('Hostname resolution of %s failed.' % mail_server)
        exit(1)
    except SMTPConnectError:
        print('Unable to connect to %s, the server refused the ' +
              'connection.' % mail_server)
        exit(1)
    # Sending the mail.
    s.sendmail(mail_sender, mail_recipients, msg.as_string())
