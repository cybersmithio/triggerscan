#!/usr/bin/python
#
# This script triggers a scan to launch through SecurityCenter.
# It will either prompt for information, read from the command line
# or read from environment variables.  It will not read passwords
# from the command line.
#
# Version 1.1a
#		Add functionality to determine if scan has completed.
#
# Version 1.1 - 2019-03-14
#        Updated to use pytenable library, use argparse, and support launching scans in Tenable.io
#
# Version 1.0 - Initial version, written by James Smith
#
# Requires the following:
#   pip install pytenable
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
import json
import argparse
from tenable.io import TenableIO
from tenable.sc import TenableSC


################################################################
# Description: Launches a scan by name
################################################################
# Input:
#        conn = the connection handle to Tenable.sc or Tenable.io
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
def LaunchScan(DEBUG,conn,scanname,scanid):
	if DEBUG:
		if scanid == "":
			print("Launching scan", scanname)
		else:
			print("Launching scan",scanid)

	#Determine if we connected to Tenable.io or Tenable.sc
	TIO = False
	if str(type(conn)) == "<class 'tenable.io.TenableIO'>":
		TIO = True

	if TIO:
		if scanid == "":
			for scan in conn.scans.list():
				if scan['name'] == scanname:
					print("Found scan ID",scan['id'],"for scan name",scan['name'])
					scanid=int(scan['id'])
		conn.scans.launch(scanid)
		return(True)
	else:
		if scanid == "":
			for scan in conn.scans.list():
				if scan['name'] == scanname:
					print("Found scan ID",scan['id'],"for scan name",scan['name'])
					scanid=int(scan['id'])
		conn.scans.launch(scanid)
		return(True)

	return(False)

#Return codes:
# 2 = other
# 1 = running
# 0 = completed
# -1 = error
#Does not currently work for Tenable.sc
def CheckScanStatus(DEBUG,conn,scanname,scanid):
	if DEBUG:
		if scanid == "":
			print("Checking scan status for ", scanname)
		else:
			print("Checking scan status for",scanid)

	#Determine if we connected to Tenable.io or Tenable.sc
	TIO = False
	if str(type(conn)) == "<class 'tenable.io.TenableIO'>":
		TIO = True

	if TIO:
		if scanid == "":
			for scan in conn.scans.list():
				if scan['name'] == scanname:
					print("Found scan ID",scan['id'],"for scan name",scan['name'])
					scanid=int(scan['id'])
		result=conn.scans.status(scanid)
		if DEBUG:
			print("Scan status:",result)
		if result == "completed":
			return(0)
		elif result == "running" or result == "stopping":
			return(1)
		elif result == "scheduled":
			return(2)

	return(-1)


#Attempts to make a connection to Tenable.sc
def ConnectSC(DEBUG,username,password,host,port):
	#Create the connection to Tenable.sc
	try:
		sc = TenableSC(host, port=port)
	except:
		print("Error connecting to SecurityCenter", sys.exc_info()[0], sys.exc_info()[1])
		return(False)

	try:
		sc.login(username, password)
	except:
		print("Error logging into to SecurityCenter", sys.exc_info()[0], sys.exc_info()[1])
		if DEBUG:
			print("Username:",username)
		return (False)

	return(sc)


#Attempts to make a connection to Tenable.io
def ConnectIO(DEBUG,accesskey,secretkey,host,port):
	#Create the connection to Tenable.io
	try:
		tio=TenableIO(accesskey, secretkey)
	except:
		print("Error connecting to Tenable.io")
		return(False)

	return(tio)


################################################################
# Start of program 
################################################################
#Set debugging on or off
DEBUG=False
ISRUN=False
parser = argparse.ArgumentParser(description="Launches a scan in Tenable.sc or Tenable.io.")
parser.add_argument('--accesskey',help="The Tenable.io access key",nargs=1,action="store")
parser.add_argument('--secretkey',help="The Tenable.io secret key",nargs=1,action="store")
parser.add_argument('--username',help="The SecurityCenter username",nargs=1,action="store")
parser.add_argument('--password',help="The SecurityCenter password",nargs=1,action="store")
parser.add_argument('--host',help="The Tenable host. (Default for Tenable.io is cloud.tenable.com)",nargs=1,action="store")
parser.add_argument('--port',help="The Tenable port. (Default is 443)",nargs=1,action="store")
parser.add_argument('--scanname',help="The name of the scan to launch.",nargs=1,action="store")
parser.add_argument('--scanid',help="The scan ID of the scan to launch.",nargs=1,action="store")
parser.add_argument('--debug',help="Turn on debugging",action="store_true")
parser.add_argument('--isrunning',help="Determine if the scan is running or not. (Does not trigger the scan)",action="store_true")
args=parser.parse_args()

if args.debug:
	DEBUG=True
	print("Debugging is enabled.")

if args.isrunning:
	ISRUN=True
	print("Checking if scan is running")


# Pull as much information from the environment variables about the system to which to connect
# Where missing then initialize the variables with a blank or pull from command line.
if os.getenv('TIO_ACCESS_KEY') is None:
	accesskey = ""
else:
	accesskey = os.getenv('TIO_ACCESS_KEY')

# If there is an access key specified on the command line, this override anything else.
try:
	if args.accesskey[0] != "":
		accesskey = args.accesskey[0]
except:
	nop = 0

if os.getenv('TIO_SECRET_KEY') is None:
	secretkey = ""
else:
	secretkey = os.getenv('TIO_SECRET_KEY')
# If there is an  secret key specified on the command line, this override anything else.
try:
	if args.secretkey[0] != "":
		secretkey = args.secretkey[0]
except:
	nop = 0


username=""
#Look for a Tenable.io username
if os.getenv('SC_USERNAME') is None:
	username = ""
else:
	username = os.getenv('SC_USERNAME')
	if DEBUG:
		print("Detected SC username")
try:
	if args.username[0] != "":
		username = args.username[0]
		if DEBUG:
			print("Detected SC username")
		#Since a specific username was found on the command line, assume the user does not want to poll Tenable.io
		secretkey = ""
		accesskey = ""
except:
	username=""

#Look for a SecurityCenter password
scpassword=""
if os.getenv('SC_PASSWORD') is None:
	scpassword = ""
else:
	scpassword = os.getenv('SC_PASSWORD')
	if DEBUG:
		print("Detected SC password")
try:
	if args.password[0] != "":
		if DEBUG:
			print("Detected SC password")
		scpassword = args.password[0]
except:
	scpassword=""

#Look for a port
port="443"
try:
	if args.port[0] != "":
		port = args.port[0]
except:
	port = "443"

#Look for a host
host="cloud.tenable.com"
try:
	if args.host[0] != "":
		host = args.host[0]
except:
	host = "cloud.tenable.com"

scanname=""
try:
	if args.scanname[0] != "":
		scanname = args.scanname[0]
except:
	scanname = ""

scanid=""
try:
	if args.scanid[0] != "":
		scanid = int(args.scanid[0])
except:
	scanid = ""


if scanname == "" and scanid == "":
	print("Need a scan name or scan ID to launch a scan:",scanid, scanname)
	exit(-1)

if scanid == "":
	print("Connecting to",host,"to launch scan ",scanname)
else:
	print("Connecting to",host,"to launch scan ID",scanid)


if accesskey != "" and secretkey != "":
	print("Connecting to cloud.tenable.com with access key", accesskey, "to report on assets")
	try:
		if args.host[0] != "":
			host = args.host[0]
	except:
		host = "cloud.tenable.com"
	conn = ConnectIO(DEBUG, accesskey, secretkey, host, port)
elif username != "" and scpassword != "":
	if DEBUG:
		print("Attempting to open connection to SC")
	try:
		if args.host[0] != "":
			host = args.host[0]
	except:
		host = "127.0.0.1"
	print("Connecting to SecurityCenter with username " + str(username) + " @ https://" + str(host) + ":" + str(port))
	conn = ConnectSC(DEBUG, username, scpassword, host, port)

if conn == False:
	print("There was a problem connecting.")
	exit(-1)

#Upload demo dashboards
if ISRUN == False:
	if LaunchScan(DEBUG,conn,scanname,scanid):
		print("Scan launched")
		exit(0)
	else:
		print("Scan not launched")
		exit(-1)
else:
	exit(CheckScanStatus(DEBUG,conn,scanname,scanid))

