#!/bin/bash
# sudo wget http://192.168.119.129:5000/api/v1/deploy/deployment_script/main_honeypot -O main_honeypot.sh && sudo bash main_honeypot.sh  webserver_ip token honeynode_name honeypot_type

WEB_SERVER_IP=$1
WEB_SERVER_PORT=$2
TOKEN=$3
HONEYNODE_NAME=$4
HONEYPOT_TYPE=$5
# NIDS_TYPE='snort'
HONEYPOT_SCRIPT_API="http://$WEB_SERVER_IP:$WEB_SERVER_PORT/api/v1/deploy/deployment_script/$HONEYPOT_TYPE"
HONEYPOT_SCRIPT_OUTPUT_FILE="deploy_${HONEYPOT_TYPE}.sh"

# NIDS_SCRIPT_API="http://$WEB_SERVER_IP:$WEB_SERVER_PORT/api/v1/deploy/deployment_script/$NIDS_TYPE"
# NIDS_SCRIPT_OUTPUT_FILE="deploy_${NIDS_TYPE}.sh"

# echo $NIDS_SCRIPT_OUTPUT_FILE

sudo wget $HONEYPOT_SCRIPT_API -O $HONEYPOT_SCRIPT_OUTPUT_FILE &&
# sudo wget $NIDS_SCRIPT_API -O $NIDS_SCRIPT_OUTPUT_FILE &&
sudo bash $HONEYPOT_SCRIPT_OUTPUT_FILE $WEB_SERVER_IP $WEB_SERVER_PORT $TOKEN $HONEYNODE_NAME &&
# sudo bash $NIDS_SCRIPT_OUTPUT_FILE