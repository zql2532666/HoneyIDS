#!/bin/bash
# sudo wget http://192.168.119.129:5000/api/v1/deploy/deployment_script/main -O main.sh && sudo bash main.sh  webserver_ip token node_name nids_type

WEB_SERVER_IP=$1
WEB_SERVER_PORT=$2
TOKEN=$3
NODE_NAME=$4
NIDS_TYPE=$5
NIDS_SCRIPT_API="http://$WEB_SERVER_IP:$WEB_SERVER_PORT/api/v1/deploy/deployment_script/$NIDS_TYPE"
NIDS_SCRIPT_OUTPUT_FILE="deploy_${NIDS_TYPE}.sh"

sudo wget $NIDS_SCRIPT_API -O $NIDS_SCRIPT_OUTPUT_FILE &&
sudo bash $NIDS_SCRIPT_OUTPUT_FILE