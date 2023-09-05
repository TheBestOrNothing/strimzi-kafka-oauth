#!/bin/bash
#hostname=$(hostname)
#if ! grep -q "127.0.0.1 $hostname" /etc/hosts; then
#    echo "127.0.0.1 $hostname" >> /etc/hosts
#fi

source /etc/profile
/opt/zookeeper/bin/zkServer.sh start
tail -f /dev/null
