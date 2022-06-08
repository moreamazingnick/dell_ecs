#!/usr/bin/env python3

# Dell ECS Health Plugin
# Tristan Self 14/12/2021
# Nicolas Schneider 08/06/2022
# The Dell ECS Health Check Plugin queries the Dell ECS API to obtain health information. It is designed to be pointed at a single cluster, but
# use of multiple checks for each cluster can be created for federation and geo-replication configuration.
# It is strongly recommended to create a read-only management account on the cluster(s) for monitoring purposes.
#
# Version 1.0 (14/12/2021) - Intital Release
# Version 1.1 (08/06/2022) - added python3 compatibility

import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import argparse
import json

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#############################################################################################
# Argument Collection
#############################################################################################

# Parse the arguments passed from the command line.
parser = argparse.ArgumentParser()
parser.add_argument('-e', '--endpointurl', help='ECS Cluster Endpoint URL (e.g. site1-ecs.domain.com)', required=True)
parser.add_argument('-u', '--username', help='Username', required=True)
parser.add_argument('-p', '--password', help='Password', required=True)

# Assign each arguments to the relevant variables.
arguments = vars(parser.parse_args())
EndpointURL = arguments['endpointurl']
APIUsername = arguments['username']
APIPassword = arguments['password']

# Initalise Variables
numNodes = 0
numGoodNodes = 0
numBadNodes = 0
numMaintenanceNodes = 0
numDisks = 0
numGoodDisks = 0
numBadDisks = 0
intCriticalCount = 0
intWarningCount = 0
alertsNumUnackCritical = 0
alertsNumUnackWarning = 0
alertsNumUnackError = 0

try:
    # Get the session cookie/token.
    response1 = requests.get('https://' + EndpointURL + ':4443/login', auth=HTTPBasicAuth(APIUsername, APIPassword),
                             verify=False)

    if response1.status_code == 200:
        # print (response1.headers)
        seshtoken = response1.headers["X-SDS-AUTH-TOKEN"]
    else:
        # print (response1)
        print("CRITICAL - Dell ECS - Failed to obtain token!")
        sys.exit(2)

    # Get the status of the cluster
    response2 = requests.get('https://' + EndpointURL + ':4443/dashboard/zones/localzone',
                             headers={"X-SDS-AUTH-TOKEN": seshtoken}, verify=False)

    objHealthJSON = json.dumps(response2.json(), indent=2)
    dictHealth = json.loads(objHealthJSON)

    numNodes = int(dictHealth['numNodes'])
    numGoodNodes = int(dictHealth['numGoodNodes'])
    numBadNodes = int(dictHealth['numBadNodes'])
    numMaintenanceNodes = int(dictHealth['numMaintenanceNodes'])
    numDisks = int(dictHealth['numDisks'])
    numGoodDisks = int(dictHealth['numGoodDisks'])
    numBadDisks = int(dictHealth['numBadDisks'])
    numMaintenanceDisks = int(dictHealth['numMaintenanceDisks'])
    alertsNumUnackWarning = int(dictHealth['alertsNumUnackWarning'][0]['Count'])
    alertsNumUnackError = int(dictHealth['alertsNumUnackError'][0]['Count'])
    alertsNumUnackCritical = int(dictHealth['alertsNumUnackCritical'][0]['Count'])

    # Logout of the session to expire the token you just got, rather than just letting it expire.
    response3 = requests.get('https://' + EndpointURL + ':4443/logout', headers={"X-SDS-AUTH-TOKEN": seshtoken},
                             verify=False)
except:
    print("CRITICAL - Dell ECS - Error connecting to the cluster! Check hostname and credentials.")
    sys.exit(2)

###############################################################################################
# Check and Output
###############################################################################################

if numBadNodes > 0:
    intCriticalCount = intCriticalCount + 1

if numMaintenanceNodes > 0:
    intWarningCount = intWarningCount + 1

if numBadDisks > 0:
    intCriticalCount = intCriticalCount + 1

if numMaintenanceDisks > 0:
    intWarningCount = intWarningCount + 1

if alertsNumUnackCritical > 0:
    intCriticalCount = intCriticalCount + 1

if alertsNumUnackWarning > 0:
    intWarningCount = intWarningCount + 1

if alertsNumUnackError > 0:
    intCriticalCount = intCriticalCount + 1

# Output to the console, with the report depending on the status of the cluster.
if intCriticalCount > 0:
    print("CRITICAL - Dell ECS Health: CRITICAL - Nodes(Good/Bad/Maint):{}/{}/{}, Disks(Good/Bad/Maint):{}/{}/{}, Alerts(Crit/Error/Warn):{}/{}/{}".format(
        numGoodNodes, numBadNodes, numMaintenanceNodes, numGoodDisks, numBadDisks, numMaintenanceDisks,
        alertsNumUnackCritical, alertsNumUnackError, alertsNumUnackWarning))
    sys.exit(2)

if intWarningCount > 0:
    print("WARNING - Dell ECS Health: DEGRADED - Nodes(Good/Bad/Maint):{}/{}/{}, Disks(Good/Bad/Maint):{}/{}/{}, Alerts(Crit/Error/Warn):{}/{}/{}".format(
        numGoodNodes, numBadNodes, numMaintenanceNodes, numGoodDisks, numBadDisks, numMaintenanceDisks,
        alertsNumUnackCritical, alertsNumUnackError, alertsNumUnackWarning))
    sys.exit(1)

if intCriticalCount == 0 and intWarningCount == 0:
    print("OK - Dell ECS Health: HEALTHY - Nodes(Good/Bad/Maint):{}/{}/{}, Disks(Good/Bad/Maint):{}/{}/{}, Alerts(Crit/Error/Warn):{}/{}/{}".format(
        numGoodNodes, numBadNodes, numMaintenanceNodes, numGoodDisks, numBadDisks, numMaintenanceDisks,
        alertsNumUnackCritical, alertsNumUnackError, alertsNumUnackWarning))
    sys.exit(0)
