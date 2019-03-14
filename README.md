# Overview
A python script to launch vulnerability scans through SecurityCenter.

Requires the pyTenable project at https://github.com/tenable/pyTenable

# How To Install
To install pyTenable, you can use either pip or easy_install to install from the cheeseshop:

  pip install pyTenable

# Running
Provide the script with login credentials for Tenable.sc or API keys for Tenable.io, and provide either a scan ID or scan name to launch.  Credentials can be supplied using environment variables (TIO_ACCESS_KEY, TIO_SECRET_KEY, SC_USERNAME, SC_PASSWORD)

# Example of running in Tenable.sc

The script will prompt for inputs if it needs information.  Everything can be supplied by environment variables.  The variables include SC_USERNAME, and SC_PASSWORD.

For example:
export SC_USERNAME=jsmith
export SC_PASSWORD=************

./triggerscan.py --scanname "My basic vuln scan" --host 192.168.1.100
