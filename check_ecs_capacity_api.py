#!/usr/bin/env python3
# Dell ECS Capacity Check Plugin
# Tristan Self 14/12/2021
# Nicolas Schneider 04/05/2022
# The Dell ECS Capacity Check Plugin queries the Dell ECS API to obtain usage information. It can be pointed at a single ECS cluster or multiple
# clusters depending on your federation and geo-replication configuration. It is strongly recommended to create a read-only management account on
# the cluster(s) for monitoring purposes.
#
# Version 1.0 (14/12/2021) - Intital Release
# Version 1.1 (04/05/2022) - added python3 compatibility
# Version 1.2 (13/05/2022) - added more check possibilities

import sys
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import argparse
import xml.etree.ElementTree as ET
from MyThreshold import *

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#############################################################################################
# Argument Collection
#############################################################################################

# Parse the arguments passed from the command line.
parser = argparse.ArgumentParser()
parser.add_argument('-e', '--endpointurl',
                    help='ECS Cluster Endpoint URLs 1 or more (e.g. site1-ecs.domain.com;site2-ecs.domain.com;site3-ecs.domain.com)',
                    required=True)
parser.add_argument('-u', '--username', help='Username', required=True)
parser.add_argument('-p', '--password', help='Password', required=True)
parser.add_argument('-w', '--warning',
                    help='Warning threshold of the cluster, or the geo-replicated storage if multiple clusters. IcingaThreshold like 0:10 in TB or Percent',
                    required=True)
parser.add_argument('-c', '--critical',
                    help='Critical threshold of the cluster, or the geo-replicated storage if multiple clusters. IcingaThreshold like 0:10 in TB or Percent',
                    required=True)
parser.add_argument('-f', '--freespace', required=False, action='store_true', default=False,
                    help='Checks for free space instead of used space')

# Assign each arguments to the relevant variables.
arguments = vars(parser.parse_args())
EndpointURL = arguments['endpointurl']
APIUsername = arguments['username']
APIPassword = arguments['password']
EndpointURL = str(EndpointURL).replace(";",",")

# Break the Endpoint URL into its various parts and put into a list.
EndpointURLs = EndpointURL.split(",", )

# Initialise the variables to hold the diskspace usage
GlobalTotalCapacity = 0
GlobalFreeSpace = 0
GlobalUsedSpace = 0
intStatus = 0
percent = False
if("%" in arguments['warning'] or "%" in arguments['critical']):
    percent = True
    arguments['warning'] = arguments['warning'].replace("%","")
    arguments['critical'] = arguments['critical'].replace("%","")
try:
    WarningThreshold = Threshold(arguments['warning'])
except:
    print("[UNKNOWN] Couldn't parse warning Threshold")
    exit(3)
try:
    CriticalThreshold = Threshold(arguments['critical'])
except:
    print("[UNKNOWN] Couldn't parse critical Threshold")
# Error handling for the whole connection loop.
try:
    # Enter a loop through the list items and
    for cluster in EndpointURLs:
        # Reset the variables for the next cluster
        cluster = cluster.strip(" ")
        TotalCapacity = 0
        FreeSpace = 0
        seshtoken = None
        response2 = None
        # Get the session cookie/token.
        response1 = requests.get('https://' + cluster + ':4443/login', auth=HTTPBasicAuth(APIUsername, APIPassword),
                                 verify=False)

        if response1.status_code == 200:
            # print (response1.headers)
            seshtoken = response1.headers["X-SDS-AUTH-TOKEN"]
        else:
            # print (response1)
            print("CRITICAL - Dell ECS - Failed to obtain token!")
            sys.exit(2)

        # Get the current capacity and usage.
        response2 = requests.get('https://' + cluster + ':4443/object/capacity',
                                 headers={"X-SDS-AUTH-TOKEN": seshtoken, "Content-Type":"application/json"}, verify=False)

        # Convert the XML to a dictionaryi
        parsedXml = ET.fromstring(response2.content.decode())

        # Get the total capacity and the used space.
        TotalCapacity = int(parsedXml.find(".//totalProvisioned_gb").text)
        FreeSpace = int(parsedXml.find(".//totalFree_gb").text)

        GlobalTotalCapacity = GlobalTotalCapacity + TotalCapacity
        GlobalFreeSpace = GlobalFreeSpace + FreeSpace

        # Logout of the session to expire the token you just got, rather than just letting it expire.
        response3 = requests.get('https://' + cluster + ':4443/logout', headers={"X-SDS-AUTH-TOKEN": seshtoken},
                                 verify=False)
    # print response3
except Exception as e:
    print(e)
    print("CRITICAL - Dell ECS - Error connecting to one or more of the clusters! Check hostname and credentials.")
    sys.exit(2)

# Calculate the global used space.
GlobalUsedSpace = GlobalTotalCapacity - GlobalFreeSpace

GlobalUsedSpacePercent = round(GlobalUsedSpace / GlobalTotalCapacity, 2) * 100
GlobalFreeSpacePercent = 100 - GlobalUsedSpacePercent
# Convert into TB rather than GB, we have alot of GB otherwise.
GlobalTotalCapacity = GlobalTotalCapacity / 1024
GlobalUsedSpace = GlobalUsedSpace / 1024
GlobalFreeSpace = GlobalFreeSpace / 1024

# Check Thresholds are not breached.
if(arguments['freespace']):
    if percent:
        if WarningThreshold.doesViolate(GlobalFreeSpacePercent):
            # Free space of cluster or clusters combined is below threshold for warning.
            intStatus = 1  # Warning
        if CriticalThreshold.doesViolate(GlobalFreeSpacePercent):
            # Free space of cluster or clusters combined is below threshold for critical.
            intStatus = 2  # Critical
    else:
        if WarningThreshold.doesViolate(GlobalFreeSpace):
            # Free space of cluster or clusters combined is below threshold for warning.
            intStatus = 1  # Warning
        if CriticalThreshold.doesViolate(GlobalFreeSpace):
            # Free space of cluster or clusters combined is below threshold for critical.
            intStatus = 2  # Critical
else:
    if percent:
        if WarningThreshold.doesViolate(GlobalUsedSpacePercent):
            # Free space of cluster or clusters combined is below threshold for warning.
            intStatus = 3  # Warning
        if CriticalThreshold.doesViolate(GlobalUsedSpacePercent):
            # Free space of cluster or clusters combined is below threshold for critical.
            intStatus = 4  # Critical
    else:
        if WarningThreshold.doesViolate(GlobalUsedSpace):
            # Free space of cluster or clusters combined is below threshold for warning.
            intStatus = 3  # Warning
        if CriticalThreshold.doesViolate(GlobalUsedSpace):
            # Free space of cluster or clusters combined is below threshold for critical.
            intStatus = 4  # Critical

#############################################################################################
# Output
#############################################################################################

# PerfDataUsedSpace = "| used="+str(GlobalUsedSpace)+"TB;"
PerfDataFreePercentWithThreshold= f"free_percent={GlobalFreeSpacePercent}%;{WarningThreshold};{CriticalThreshold};0;100"
PerfDataFreePercentWithoutThreshold= f"free_percent={GlobalFreeSpacePercent}%;;;0;100"

PerfDataFreeSpaceWithThreshold= f"free={GlobalFreeSpace}TB;{WarningThreshold};{CriticalThreshold};0;{GlobalTotalCapacity}"
PerfDataFreeSpaceWithoutThreshold= f"free={GlobalFreeSpace}TB;;;0;{GlobalTotalCapacity}"

PerfDataUsedPercentWithThreshold= f"used_percent={GlobalUsedSpacePercent}%;{WarningThreshold};{CriticalThreshold};0;100"
PerfDataUsedPercentWithoutThreshold= f"used_percent={GlobalUsedSpacePercent}%;;;0;100"

PerfDataUsedSpaceWithThreshold= f"used={GlobalUsedSpace}TB;{WarningThreshold};{CriticalThreshold};0;{GlobalTotalCapacity}"
PerfDataUsedSpaceWithoutThreshold= f"used={GlobalUsedSpace}TB;;;0;{GlobalTotalCapacity}"
PerfData = " |"
if arguments['freespace']:
    PerfData += " " + PerfDataUsedPercentWithoutThreshold
    PerfData += " " + PerfDataUsedSpaceWithoutThreshold

    if percent:
        PerfData += " "+PerfDataFreePercentWithThreshold
        PerfData += " " + PerfDataFreeSpaceWithoutThreshold
    else:
        PerfData += " " + PerfDataFreeSpaceWithThreshold
        PerfData += " " + PerfDataFreePercentWithoutThreshold

else:
    PerfData += " " + PerfDataFreeSpaceWithoutThreshold
    PerfData += " " + PerfDataFreePercentWithoutThreshold
    if percent:
        PerfData += " " + PerfDataUsedPercentWithThreshold
        PerfData += " " + PerfDataUsedSpaceWithoutThreshold
    else:
        PerfData += " " + PerfDataUsedSpaceWithThreshold
        PerfData += " " + PerfDataUsedPercentWithoutThreshold


if intStatus == 0:
    # All is well, report OK.
    print("OK - Dell ECS - Total: {} TB, Free: {} TB, Used: {} TB - Space Normal {}".format(GlobalTotalCapacity,
                                                                                           GlobalFreeSpace,
                                                                                           GlobalUsedSpace,
                                                                                           PerfData))
    sys.exit(0)

if intStatus == 1:
    # Below warning threshold, report this back.
    print("WARNING - Dell ECS - Total: {} TB, Free: {} TB, Used: {} TB - Free Space Warning! {}".format(GlobalTotalCapacity,
                                                                                                  GlobalFreeSpace,
                                                                                                  GlobalUsedSpace,
                                                                                                  PerfData))
    sys.exit(1)

if intStatus == 2:
    # Below critical threshold, report this back.
    print("CRITICAL - Dell ECS - Total: {} TB, Free: {} TB, Used: {} TB - Free Space Critical! {}".format(GlobalTotalCapacity,
                                                                                                    GlobalFreeSpace,
                                                                                                    GlobalUsedSpace, PerfData))
    sys.exit(2)
if intStatus == 3:
    # Below warning threshold, report this back.
    print("WARNING - Dell ECS - Total: {} TB, Free: {} TB, Used: {} TB - Used Space Warning! {}".format(GlobalTotalCapacity,
                                                                                                  GlobalFreeSpace,
                                                                                                  GlobalUsedSpace,
                                                                                                  PerfData))
    sys.exit(1)

if intStatus == 4:
    # Below critical threshold, report this back.
    print("CRITICAL - Dell ECS - Total: {} TB, Free: {} TB, Used: {} TB - Used Space Critical! {}".format(GlobalTotalCapacity,
                                                                                                    GlobalFreeSpace,
                                                                                                    GlobalUsedSpace, PerfData))
    sys.exit(2)
