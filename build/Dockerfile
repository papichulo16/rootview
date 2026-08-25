FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y make gcc flex git libyaml-dev gdb

# libvmi dependencies
RUN apt-get install -y cmake bison pkg-config libglib2.0-dev libvirt-dev libvirt-clients libjson-c-dev libyajl-dev

WORKDIR /

RUN git clone https://github.com/KVM-VMI/kvm-vmi --recursive
RUN cd kvm-vmi/libvmi && mkdir build && cd build && \
    cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DENABLE_XEN=OFF -DBUILD_EXAMPLES=OFF .. && \
    make -j$(nproc) && make install && ldconfig

# make install's pkgconfig file doesn't always land somewhere pkg-config
# looks by default - the Makefile needs `pkg-config --cflags/--libs libvmi`
# to work for headers and dynamic linking.
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib/x86_64-linux-gnu/pkgconfig:/usr/local/share/pkgconfig

RUN rm -rf /var/lib/apt/lists/*

VOLUME /root/env
WORKDIR /root/env

