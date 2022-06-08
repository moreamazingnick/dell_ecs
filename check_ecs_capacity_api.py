#!/usr/bin/env python
# Dell ECS Capacity Check Plugin
# Tristan Self 14/12/2021
# The Dell ECS Capacity Check Plugin queries the Dell ECS API to obtain usage information. It can be pointed at a single ECS cluster or multiple
# clusters depending on your federation and geo-replication configuration. It is strongly recommended to create a read-only management account on
# the cluster(s) for monitoring purposes.
#
# Version 1.0 (14/12/2021) - Intital Release

import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import json
import argparse
import xmltodict

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#############################################################################################
# Argument Collection
#############################################################################################

# Parse the arguments passed from the command line.
parser = argparse.ArgumentParser()
parser.add_argument('-e','--endpointurl',help='ECS Cluster Endpoint URLs 1 or more (e.g. site1-ecs.domain.com;site2-ecs.domain.com;site3-ecs.domain.com)',required=True)
parser.add_argument('-u','--username',help='Username',required=True)
parser.add_argument('-p','--password',help='Password',required=True)
parser.add_argument('-w','--warning',help='Free space warning threshold of the cluster, or the geo-replicated storage if multiple clusters. Integer in TB.',required=True)
parser.add_argument('-c','--critical',help='Free space critical theshold of the cluster, or the geo-replicated storage if multiple clusters. Integer in TB.',required=True)


# Assign each arguments to the relevant variables.
arguments = vars(parser.parse_args())
EndpointURL = arguments['endpointurl']
APIUsername = arguments['username']
APIPassword = arguments['password']
WarningThreshold = int(arguments['warning'])
CriticalThreshold = int(arguments['critical'])

# Break the Endpoint URL into its various parts and put into a list.
EndpointURLs = EndpointURL.split(",",)

# Initialise the variables to hold the diskspace usage
GlobalTotalCapacity = 0
GlobalFreeSpace = 0
GlobalUsedSpace = 0
intStatus = 0

# Error handling for the whole connection loop.
try:
	# Enter a loop through the list items and 
	for cluster in EndpointURLs:
		#Reset the variables for the next cluster
		TotalCapacity = 0
		FreeSpace = 0
		seshtoken = None
		response1 = None
		response2 = None
		response3 = None
		# Get the session cookie/token.
		response1 = requests.get('https://' + cluster + ':4443/login',auth = HTTPBasicAuth(APIUsername,APIPassword),verify=False)

		if response1.status_code == 200:
        		#print (response1.headers)
		        seshtoken = response1.headers["X-SDS-AUTH-TOKEN"]
		else:
        		#print (response1)
		        print "CRITICAL - Dell ECS - Failed to obtain token!"
			sys.exit(2)

		# Get the current capacity and usage.
        	response2 = requests.get('https://' + cluster + ':4443/object/capacity',headers={"X-SDS-AUTH-TOKEN":seshtoken},verify=False)

	        #Convert the XML to a dictionary
	        dictCapacity = xmltodict.parse(response2.content)

	        # Get the total capacity and the used space.
	        TotalCapacity = int(dictCapacity['cluster_capacity']['totalProvisioned_gb'])
	        FreeSpace = int(dictCapacity['cluster_capacity']['totalFree_gb'])
	        GlobalTotalCapacity = GlobalTotalCapacity + TotalCapacity
	        GlobalFreeSpace = GlobalFreeSpace + FreeSpace
	
        	# Logout of the session to expire the token you just got, rather than just letting it expire.
	        response3 = requests.get('https://' + cluster + ':4443/logout',headers={"X-SDS-AUTH-TOKEN":seshtoken},verify=False)
        	#print response3
except:
	print "CRITICAL - Dell ECS - Error connecting to one or more of the clusters! Check hostname and credentials."
	sys.exit(2)

# Calculate the global used space.
GlobalUsedSpace = GlobalTotalCapacity - GlobalFreeSpace

# Convert into TB rather than GB, we have alot of GB otherwise.
GlobalTotalCapacity = GlobalTotalCapacity / 1024
GlobalUsedSpace = GlobalUsedSpace / 1024
GlobalFreeSpace = GlobalFreeSpace / 1024

# Check Thresholds are not breached.
if GlobalFreeSpace <= WarningThreshold:
	# Free space of cluster or clusters combined is below threshold for warning.
	intStatus = 1 # Warning
if GlobalFreeSpace <= CriticalThreshold:
	# Free space of cluster or clusters combined is below threshold for critical.
	intStatus = 2 # Critical

#############################################################################################
# Output
#############################################################################################

#PerfDataUsedSpace = "| used="+str(GlobalUsedSpace)+"TB;"
PerfDataUsedSpace = "| used={}TB;{};{};0;{}".format(str(GlobalUsedSpace),str(WarningThreshold),str(CriticalThreshold),str(GlobalTotalCapacity))

if intStatus == 0:
	# All is well, report OK.
	print "OK - Dell ECS - Total: {} TB, Free: {} TB, Used: {} TB - Free Space Normal {}".format(GlobalTotalCapacity,GlobalFreeSpace,GlobalUsedSpace,PerfDataUsedSpace)
	sys.exit(intStatus)

if intStatus == 1:
	# Below warning threshold, report this back.
	print "WARNING - Dell ECS - Total: {} TB, Free: {} TB, Used: {} TB - Free Space Warning! {}".format(GlobalTotalCapacity,GlobalFreeSpace,GlobalUsedSpace,PerfDataUsedSpace)
	sys.exit(intStatus)	

if intStatus == 2:
	# Below critical threshold, report this back.
	print "CRITICAL - Dell ECS - Total: {} TB, Free: {} TB, Used: {} TB - Free Space Critical! {}".format(GlobalTotalCapacity,GlobalFreeSpace,GlobalUsedSpace),PerfDataUsedSpace
	sys.exit(intStatus)	
