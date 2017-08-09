# Overview
A python script to launch vulnerability scans through SecurityCenter.

Requires the pySecurityCenter project at https://github.com/SteveMcGrath/pySecurityCenter

# How To Install
To install pySecurityCenter, you can use either pip or easy_install to install from the cheeseshop:
  pip install pysecuritycenter

  easy_install pysecuritycenter

# Running
The script requires an IP or hostname, a set of user credentials with privileges to run a scan, and the *exact* name of the scan to run.  Remember that scan names are case sensitive.

# How To Run Without Prompts

The script will prompt for inputs if it needs information.  Everything can be supplied by environment variables.  The variables include SCHOST, SCUSERNAME, SCSCAN, and SCPASSWORD.

For example:

SCHOST=192.168.1.1; export SCHOST

SCUSERNAME=jamessmith;export SCUSERNAME

SCSCAN="Host discovery with OS ID"; export SCSCAN

SCPASSWORD=************ ; export SCPASSWORD

./triggerscan.py
