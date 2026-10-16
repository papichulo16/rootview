# RootView
## KVM-based eBPF Linux Rootkit Detection Engine

haur haur haur haur haur haur haur

### Init
You need to set up bare-metal KVM-VMI, we have a VM with it all set up in `RELEASES`. But if you need to do it yourself for your machine, [just follow this guide](https://kvm-vmi.github.io/kvm-vmi/kvmi-v7/setup.html)

#### Docker building
Build inside docker image built in `build/Dockerfile`. This docker container should setup LibVMI for you.

build docker container: `docker build build -t rootview`

run docker container: `docker run --rm -it -v $(pwd):/root/env rootview /bin/bash`

inside docker container run `make all`

Afterwards, just run the tool outside the docker container.

#### Usage

You will need to install an `iso` file in order to introspect into that `iso's` VM. 
 - `./rv vm [args]` - will set up your VM. Here is a default one I like: `./rv vm create test --cdrom [iso path] --display gtk`
