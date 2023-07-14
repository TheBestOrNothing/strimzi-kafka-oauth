#!/bin/bash

host=`hostname`

if [ "$host" == "zookeeper" ]; then
    source /etc/profile
    cd /kafka/
    bin/zookeeper-server-start.sh config/zookeeper.properties

elif [ "$host" == "kafka" ]; then
    source /etc/profile
    cd /kafka/authLibs/

    if ! grep -q "OAUTH_ACCESS_TOKEN=" /etc/profile; then
        output=$(java -cp ./*: io.strimzi.kafka.oauth.client.KafkaAdminToken)
        echo "export OAUTH_ACCESS_TOKEN=\"$output\"" >> /etc/profile
        source /etc/profile
    fi

    cd /kafka/
    sleep 3s
    bin/kafka-server-start.sh config/server.properties

else
    echo "Invalid host name"

fi
exec "$@"
