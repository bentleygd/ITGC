#!/usr/bin/python3
from re import search
from socket import gethostbyname, gaierror
from smtplib import SMTP, SMTPConnectError
from email.mime.text import MIMEText


class getConfig:
    """A configuration class"""
    def __init__(self, file_location):
        self.fn = file_location

    def GetMailSender(self):
        """Gets mail sender"""
        config = open(self.fn, 'r', encoding='ascii')
        for line in config:
            sender = search(r'(MailSender: )(.+)', line)
            if sender:
                return sender.group(2)
        config.close()

    def GetReportRcpts(self):
        """Gets report recipients"""
        config = open(self.fn, 'r', encoding='ascii')
        for line in config:
            rcpts = search(r'(Recipients: )(.+)', line)
            if rcpts:
                return rcpts.group(2)
        config.close()

    def GetSMTPServer(self):
        """Get a SMTP server name from config"""
        config = open(self.fn, 'r', encoding='ascii')
        for line in config:
            smtpserver = search(r'(SMTP: )(.+)', line)
            if smtpserver:
                return smtpserver.group(2)
        config.close()

    def GetSysUser(self):
        """Docstring goes here."""
        config = open(self.fn, 'r', encoding='ascii')
        for line in config:
            user = search(r'(SYS_USER: )(.+)', line)
            if user:
                return user.group(2)
        config.close()


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
