#FROM registry.cn-hangzhou.aliyuncs.com/imagesdd/centos7.6-kafka:3.4.1
FROM registry.cn-hangzhou.aliyuncs.com/imagesdd/ubuntu22.04-kafka:v3
RUN mkdir -p /kafka/authLibs
RUN mkdir -p /tmp/ssl

COPY ./ssl/* /tmp/ssl/
COPY ./kafka/libs-client/* /kafka/authLibs/
COPY ./kafka/libs-common/* /kafka/authLibs/
COPY ./kafka/libs-producer/bctls-jdk18on-1.76.jar /kafka/authLibs/
COPY ./kafka/libs-producer/bcutil-jdk18on-1.76.jar /kafka/authLibs/
COPY ./kafka/target/libs/* /kafka/authLibs/

RUN echo "CLASSPATH=$CLASSPATH:/kafka/authLibs/*">>/etc/profile
#RUN source /etc/profile
RUN . /etc/profile
COPY ./config/* /kafka/config/
COPY ./kafka/start.sh /kafka/
RUN chmod +x /kafka/start.sh

RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

ENTRYPOINT ["bash", "/kafka/start.sh"]
