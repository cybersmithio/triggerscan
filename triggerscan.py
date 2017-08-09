#!/usr/bin/python
#
# This script triggers a scan to launch through SecurityCenter.
# It will either prompt for information, read from the command line
# or read from environment variables.  It will not read passwords
# from the command line.
#
# Version 1.0
#
# Roadmap
#   
# Sample usage:
#
# SCHOST=192.168.1.1; export SCHOST
# SCUSERNAME=jamessmith;export SCUSERNAME
# SCSCAN="Host discovery with OS ID"; export SCSCAN
# SCPASSWORD=***********;export SCPASSWORD
# ./triggerscan.py
#


import sys
import os
import re
import string
import json
from datetime import datetime,date, time
import requests
from securitycenter import SecurityCenter5
		
		
################################################################
# Description: Launches a scan by name
################################################################
# Input:
#        scsm = the SecurityCenter Security Manager session object
#        scan = The name of the scan to launch
#
################################################################
# Output:
#        True = Successfully completed operation
#        False = Did not successfully complete the operation
################################################################
# To do:
#        Put the scan name in the scan list filter
#
################################################################
def LaunchScan(scsm,scan):
	#First upload the XML file, then tell SC to import it.
	DEBUG=False
	if DEBUG:
		print "Launching scan",scan

	resp=scsm.get('scan?filter=usable&fields=canUse%2CcanManage%2Cowner%2Cgroups%2CownerGroup%2Cstatus%2Cname%2CcreatedTime%2Cschedule%2Cpolicy%2Cplugin%2Ctype')

	if DEBUG:
		print resp
		print resp.text
	respdata=json.loads(resp.text)
	scanlist=respdata['response']['usable']
	if DEBUG:
		print "\n\nResponse error code/error message",respdata['error_code'],"/",respdata['error_msg']
		print "\n\nScan list",scanlist

	scanid=0
	for i in scanlist:
		if DEBUG:
			print "Scan:"
			print "id:",i['id']
			print "name:",i['name']
			print "\n"
		if i['name'] == scan:
			scanid=int(i['id'])
			if DEBUG:
				print "Found scan! ID is:",i['id']
			

	if scanid != 0:
		if DEBUG:
			print "Scan ID is:",str(scanid)
		resp=scsm.post('scan/'+str(scanid)+'/launch')
		return(True)
	else:
		print "Scan not found"

	return(False)

		

################################################################
# Start of program 
################################################################
#Set debugging on or off
DEBUG=False

#Pull as much information from the environment variables
# as possible, and where missing then initialize the variables.
if os.getenv('SCHOST') is None:
	schost=""
else:
	schost=os.getenv('SCHOST')
	if DEBUG:
		print "Found SCHOST variable:",schost

if os.getenv('SCUSERNAME') is None:
	username=""
else:
	username=os.getenv('SCUSERNAME')

if os.getenv('SCPASSWORD') is None:
	password=""
else:
	password=os.getenv('SCPASSWORD')

if os.getenv('SCSCAN') is None:
	scan=""
else:
	scan=os.getenv('SCSCAN')

if DEBUG:
	print "Connecting to",schost,"as",username,"to launch scan",scan

#Pull information from command line.  If nothing there,
# and there was nothing in the environment variables, then ask user.
if len(sys.argv) > 1:
	schost=sys.argv[1]
else:
	if schost == "":
		schost=raw_input("SC Host:")

if len(sys.argv) > 2:
	username=sys.argv[2]
else:
	if username == "":
		username=raw_input("Username:")

if len(sys.argv) > 3:
	scan=sys.argv[3]
else:
	if scan == "":
		scan=raw_input("Scan To Launch:")

if password == "":
	password=raw_input("Password:")


print "Connecting to",schost,"as",username,"to launch scan",scan

#Create a session as the user
scsm=SecurityCenter5(schost)
scsm.login(username,password)
if DEBUG:
	print "Logged in as "+str(username)+" to SecurityCenter at "+str(schost)

#Upload demo dashboards
if LaunchScan(scsm,scan):
	print "Scan launched"
	exit(0)
else:
	print "Scan not launched"
	exit(-1)


