FROM ubuntu
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y make gcc flex git libyaml-dev gdb

# libvmi dependencies 
RUN apt-get install -y cmake bison libglib2.0-dev libvirt-dev libjson-c-dev libyajl-dev

WORKDIR /

RUN git clone https://github.com/tlsa/libcyaml.git /tmp/libcyaml \
    && cd /tmp/libcyaml \
    && make \
    && make install \
    && ldconfig \
    && rm -rf /tmp/libcyaml

WORKDIR /

RUN git clone https://github.com/KVM-VMI/kvm-vmi --recursive && \
    cd kvm-vmi/libvmi && mkdir build && cd build && cmake .. && \
    make -j$(nproc) && make install && ldconfig

RUN rm -rf /var/lib/apt/lists/*

VOLUME /root/env
WORKDIR /root/env

