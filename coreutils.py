#!/usr/bin/python3
from re import search
from socket import gethostbyname
from smtplib import SMTP
from email.mime.text import MIMEText


class getConfig:
    """A configuration class"""
    def __init__(self, file_location):
        self.fn = file_location

    def GetMailSender(self):
        """Gets mail sender"""
        config = open(self.fn, 'r+b')
        for line in config:
            sender = search(r'(MailSender: )(.+)', line)
            if sender:
                return sender.group(2)
        config.close()

    def GetReportRcpts(self):
        """Gets report recipients"""
        config = open(self.fn, 'r+b')
        for line in config:
            rcpts = search(r'(Recipients: )(.+)', line)
            if rcpts:
                return rcpts.group(2)
        config.close()

    def GetSMTPServer(self):
        """Get a SMTP server name from config"""
        config = open(self.fn, 'r+b')
        for line in config:
            smtpserver = search(r'(SMTP: )(.+)', line)
            if smtpserver:
                return smtpserver.group(2)
        config.close()


def mailSend(mail_sender, mail_recipients, subject, mail_server, mail_body):
    """Simple function to send mail."""
    # Defining mail properties.
    msg = MIMEText(mail_body)
    msg['Subject'] = subject
    msg['From'] = mail_sender
    msg['To'] = mail_recipients
    # Obtaining IP address of SMTP server host name.  If using an IP
    # address, omit the gethostbyname function.
    s = SMTP(gethostbyname(mail_server), '25')
    # Sending the mail.
    s.sendmail(mail_sender, mail_recipients, msg.as_string())
