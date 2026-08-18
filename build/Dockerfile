FROM ubuntu
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y make gcc git gdb

VOLUME /root/env
WORKDIR /root/env

