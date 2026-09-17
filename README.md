# RootView
## KVM-based eBPF Linux Rootkit Detection Engine

haur haur haur haur haur haur haur

### Init
If you want to set up bare-metal KVM-VMI you need to do it yourself for your machine, [just follow this guide](https://kvm-vmi.github.io/kvm-vmi/kvmi-v7/setup.html). Either way they should both expose the same API so it should not stop the tool from working.
 - *NOTE: bare-metal setup is recommended, if not you will need to have the libVMI `.so` files running in the same directory as the binary (if rrunning on host)*

Build inside docker image built in `build/Dockerfile`. This docker container should setup LibVMI for you.

build docker container: `docker build build -t rootview`

run docker container: `docker run --rm -it -v $(pwd):/root/env rootview /bin/bash`

inside docker container run `make all`

Afterwards, just run the tool outside the docker container.

