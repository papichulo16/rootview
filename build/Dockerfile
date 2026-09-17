# Must match the glibc of the machine that RUNS rv (README: run outside the container).
# ubuntu:latest drifted to 26.04/glibc 2.43 and produced binaries the 22.04 host
# could not load: version `GLIBC_2.38' not found.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
      make gcc flex git libyaml-dev gdb \
      cmake bison pkg-config libglib2.0-dev libvirt-dev libvirt-clients \
      libjson-c-dev libyajl-dev \
      autoconf automake libtool \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /

RUN git clone --depth 1 https://github.com/KVM-VMI/kvm-vmi.git \
 && cd kvm-vmi \
 && git submodule update --init libvmi libkvmi

# Install libkvmi so that one can actually introspect
RUN cd kvm-vmi/libkvmi \
 && ./bootstrap \
 && ./configure --prefix=/usr/local \
 && make -j"$(nproc)" && make install && ldconfig

RUN cd kvm-vmi/libvmi && mkdir build && cd build && \
    cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DENABLE_XEN=OFF -DBUILD_EXAMPLES=OFF -DENABLE_STATIC=ON .. && \
    make -j$(nproc) && make install && ldconfig

# make install's pkgconfig file doesn't always land somewhere pkg-config
# looks by default - the Makefile needs `pkg-config --cflags/--libs libvmi`
# to work both for headers and for the static-link deps.
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib/x86_64-linux-gnu/pkgconfig:/usr/local/share/pkgconfig

VOLUME /root/env
WORKDIR /root/env
