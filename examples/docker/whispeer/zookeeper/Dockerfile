#FROM registry.cn-hangzhou.aliyuncs.com/imagesdd/centos7.6-zookeeper
FROM registry.cn-hangzhou.aliyuncs.com/imagesdd/ubuntu22.04-zookeeper:v1
#COPY ./config/* /zookeeper/config/
COPY ./zookeeper/start.sh /opt/zookeeper/
RUN chmod +x /opt/zookeeper/start.sh
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
ENTRYPOINT ["bash", "/opt/zookeeper/start.sh"]
