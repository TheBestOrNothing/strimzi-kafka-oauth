#!/bin/bash

# build all libs
mvn clean install -DskipTests

# install libs
mkdir kafka
mkdir kafka/authLibs
mkdir kafka/config
# Copy files to the destination directory
cp ./oauth-server/target/kafka-oauth-server-1.0.0-SNAPSHOT*.jar ./kafka/authLibs
cp ./oauth-client/target/kafka-oauth-client-1.0.0-SNAPSHOT*.jar ./kafka/authLibs
cp ./oauth-keycloak-authorizer/target/kafka-oauth-keycloak-authorizer-1.0.0-SNAPSHOT*.jar ./kafka/authLibs
cp ./oauth-common/target/kafka-oauth-common-1.0.0-SNAPSHOT*.jar ./kafka/authLibs
cp ./oauth-common/target/lib/* ./kafka/authLibs

# install kafak and config
# curl -o ./kafka/kafka.tgz https://downloads.apache.org/kafka/3.4.0/kafka_2.13-3.4.0.tgz
file_path="./kafka/kafka.tgz"
url="https://downloads.apache.org/kafka/3.4.1/kafka_2.12-3.4.1.tgz"
if [ ! -f "$file_path" ]; then
    curl -o "$file_path" "$url"
else
    echo "File already exists: $file_path"
fi

tar -xzvf ./kafka/kafka.tgz --strip-components=1 -C ./kafka/
#rm  kafka/kafka_2.13-3.4.0.tgz
cp ./config/* ./kafka/config/
