FROM registry.cn-hangzhou.aliyuncs.com/imagesdd/centos7.6-jdk:1.8.0_333
RUN mkdir -p /kafka/authLibs

copy ./libs/* /kafka/authLibs/
COPY ./target/libs/* /kafka/authLibs/

RUN echo "CLASSPATH=/kafka/authLibs/*">>/etc/profile
RUN source /etc/profile
RUN curl -o "/kafka/kafka.tgz" "https://downloads.apache.org/kafka/3.4.1/kafka_2.13-3.4.1.tgz"
#COPY ./kafka.tgz /kafka/

RUN tar -xzvf /kafka/kafka.tgz --strip-components=1 -C ./kafka/
COPY ./config/* /kafka/config/
RUN rm -rf /kafka/kafka.tgz
COPY ./start.sh /kafka/
RUN chmod +x /kafka/start.sh
ENTRYPOINT ["bash", "/kafka/start.sh"]
