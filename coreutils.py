#!/usr/bin/python3
from socket import gethostbyname
from smtplib import SMTP
from email.mime.text import MIMEText


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
