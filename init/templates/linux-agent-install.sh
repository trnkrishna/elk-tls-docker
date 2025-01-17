#!/bin/bash
#########################################################
#  Elastic Agent Ubuntu Install Steps using apt
#		by David Walden (Rainiur)
#  These steps will: 
#  Add the Elastic Repository to apt
#  Download and install the elastic agent
#  Download the certificate from the server via scp
#       (This script will register a self-signed cert if you are using a 3rd party signed cert delete --insecure from the elastic-agent install)
#  Add the certificate
#  And run the install to register it to your Fleet manager
#
#  You will need the following
#		- ssh credentials, filename and IP for the server with your cert 
#			(best to copy the cert to the root directory of the user)
#		- IP address of your Fleet Server
#		- Token for the policy to apply to the system
#
#########################################################

cp ca.crt /usr/local/share/ca-certificates/

## Add the cert
update-ca-certificates

## Download and install the tarball image
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-7.15.1-linux-x86_64.tar.gz
tar xzvf elastic-agent-7.16.1-linux-x86_64.tar.gz

## Since the agent was installed via apt we just need to enroll with the Fleet Server
cd elastic-agent-7.16.1-linux-x86_64
./elastic-agent install -f --url=https://FLEET_SERVER_IP:8220 --insecure --enrollment-token=ENROLL_TOKEN

## Restart and enable the service
systemctl start elastic-agent.service
systemctl enable elastic-agent.service

cd ..
rm -rf elastic*
