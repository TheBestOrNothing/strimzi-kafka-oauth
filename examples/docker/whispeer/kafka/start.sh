#!/bin/bash

source /etc/profile
cd /kafka/authLibs/

if ! grep -q "OAUTH_ACCESS_TOKEN=" /etc/profile; then
#        output=$(java -cp ./*: io.strimzi.kafka.oauth.client.KafkaAdminToken)
    output=$(java -cp ./*: io.strimzi.kafka.oauth.client.Web3AdminToken)
    echo "export OAUTH_ACCESS_TOKEN=\"$output\"" >> /etc/profile
    source /etc/profile
fi

hostname=$(hostname)
if ! grep -q "127.0.0.1 $hostname" /etc/hosts; then
    echo "127.0.0.1 $hostname" >> /etc/hosts
fi

cd /kafka/
#sleep 3s
#bin/kafka-server-start.sh -daemon config/server.properties
bin/kafka-server-start.sh config/server.properties

tail -f /dev/null
#exec "$@"
