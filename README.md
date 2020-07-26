# ITGC
Python scripts used for SOX ITGCs.  These scripts are designed to assist in automating user security reviews for Unix based systems and Oracle databases.  Other useful audits are included as well (see below for details).

[![Known Vulnerabilities](https://snyk.io/test/github/bentleygd/ITGC/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/bentleygd/ITGC?targetFile=requirements.txt)[![Total alerts](https://img.shields.io/lgtm/alerts/g/bentleygd/ITGC.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bentleygd/ITGC/alerts/)[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/bentleygd/ITGC.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bentleygd/ITGC/context:python)![Lint and Test](https://github.com/bentleygd/ITGC/workflows/Lint%20and%20Test/badge.svg)

# Motivation
This project was started to automate user security reviews (and other audits) that may be taken as part of IT General Control testing for SOX compliance.  Automating these audits has the following benefits:  

- Allows IT operations staff to focus on tasks more suited to their expertise.
- Increases confidence in the results of the audit by reducing or eliminating human error.
- Allows for "continuous" auditing, giving business leadership confidence that IT controls are being implemented and followed.
- Reduces the number of man hours required to execute audit activities, resulting in financial savings.

# Install

`$ git clone https://github.com/bentleygd/ITGC.git`

# Usage
In order to run the user security review scripts run:  
`$ python3 itgc.py [OS]`  
The current operating systems which there are audit tests for are AIX, Linux and Oracle DB.  

> usage: itgc.py [-h] os  
> SOX ITGC User Security Reviews
>
> positional arguments:
>  os          Linux, AIX or Oracle
>
>optional arguments:
>  -h, --help  show this help message and exit

# Documentation
See DOCS.md for more detailed documentation.

# Features
- Automated security reviews for Linux, AIX and Oracle DBs.  
<h2>AIX/Linux</h2>
<h3>AIX/Linux User Auditing</h3>
Linux user accounts are compared to a list of accounts that are retrieved from Active Directory using.  Any Linux account that has a valid login shell that does not have a corresponding active directory account is flagged as an audit finding.  A list of local accounts must be maintained for exceptions to the audit process (e.g., root).

<h3>AIX/Linux Group Auditing</h3>
Group membership of specifc groups specified in the [Linux] section of the configuration file are audited as well.  The specified groups must have a file containing the expected members of the admin group.  Otherwise, all memembers of the groups will be flagged as an audit exception.

***

<h2>Oracle DB</h2>
<h3>Oracle DB User Auditing</h3>
Oracle DB user accounts are compared to a list of accounts that are retrieved from Active Directory using ldap3.  Any DB account that does not have a corresponding active directory account is flagged as an audit finding.  A list of local DB accounts must be maintained for exceptions to the audit process (e.g., Oracle).

<h3>DBA Granted Role Auditing</h3>
Oracle DB users with the DBA granted role are compared to a list of users that are expected to have the DBA granted role.  Any exceptions are noted as an audit finding.

<h3>User Profile Auditing</h3>
Any user that is considered an "air breather" that has SCHEMA_PROF is flagged as an audit finding.  Additionally, any account with the DEFAULT profile is flagged as an audit finding as users should receive a distinct DB profile.

***

<h2>Report Delivery</h2>
Currently, the audit results are parsed from CSV files and are emailed to an address specified in the [mail] section of the configuration file.

# Testing
Automated test cases are included and use the pytest framework.  Executing the tests is simple:  
`$ python3 -m pytest -v`

# License
This projct is licensed under GPLv3.