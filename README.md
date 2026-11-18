# RootView - KVM-based eBPF Linux Rootkit Detection Engine

![logo.png](images/logo.png)

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

#### Python lib
`./setup-python.sh` builds `librootview.so` and installs `rootview` into `.venv`. Then `. .venv/bin/activate`.

#### Phone (pkvm-vmi)
rootview can also read a Pixel's own kernel from EL2 through [pkvmi-mod](../pkvmi-mod): flash its `local` build, put its CLI at `/data/local/tmp/pkvmi`, and have `adb` on `PATH` with the phone rooted (`su`). Then `Rootview("pkvm-vmi")` instead of `Rootview("kvm-vmi", "myvm")`; the API is the same. From inside the kvmi-vm, reach the host's adb server with `ADB_SERVER_SOCKET=tcp:10.0.2.2:5037`.

#### Web server
`./run-web.sh` builds the lib and serves on http://127.0.0.1:8000 (`ROOTVIEW_PORT` to change it).
