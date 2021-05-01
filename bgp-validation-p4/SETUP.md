# VM Setup

## Preparing the environment
The old VM was outdated (Ubuntu 14.04 LTS is currently in extended security support and does not support Python >3.5) and in many cases the setup instructions were wrong, so this guide will go through how to create a VM with modern software support.

* First, grab a copy of the Ubuntu 20.04 LTS ISO. I used the [mini net-install image](http://archive.ubuntu.com/ubuntu/dists/focal/main/installer-amd64/current/legacy-images/netboot/mini.iso) for a headless install.
* Create a new VM. I used 1GB of RAM, 1 CPU core and 20GB of disk space connected to SCSI, but this is not important. If the VM asks what operating system it will run, select Ubuntu x64.
* Install Ubuntu 20.04 normally, then boot and log in to the environment.
* Install base dependencies:
  ```
  sudo apt update
  sudo apt install python-is-python3 python3-pip quagga-core quagga-bgpd mininet
  ```
* Add the third party repository containing Ubuntu 20.04 ports of P4Lang packages:
  ```
  sudo apt install software-properties-common
  sudo add-apt-repository ppa:frederic-loui/p4lang-3rd-party-focal
  sudo add-apt-repository ppa:frederic-loui/p4lang-master-focal-nightly
  sudo apt update
  sudo apt-get install p4lang-pi bmv2 p4c ptf
  ```

This should get you to a working environment containing everything you need (P4, Mininet, OVSwitch, etc.).

### Optional: Recompile bmv2 for better performance
The `bmv2` package above is not compiled with the correct C++ flags for best performance (see [here](https://github.com/p4lang/behavioral-model/blob/main/docs/performance.md)). To ensure optimal performance, we must recompile `bmv2` ourselves, with the correct `CPPFLAGS`. Fortunately, by installing the packages above, we should have (almost) all prerequisites except `build-essential`, which provides the requisite toolchain. 

To recompile `bmv2`, we must do the following:

* Check out the latest copy of the repository: `git clone git@github.com:p4lang/behavioral-model.git ; cd behavioral-model`
* Switch to the branch corresponding to the version of `bmv2` we would like to compile (1.14.x in this case): `git checkout origin/1.14.x`
* Run the following to start the build:
```
./autogen.sh
./configure 'CXXFLAGS=-g -O3' 'CFLAGS=-g -O3' --disable-logging-macros --disable-elogger
make
```
* Finally, install the copy of `bmv2` we have just compiled over the package-provided copy: `sudo make install`

The difference is substantial: running `curl` to pull a 790KB file previously yielded a throughput of about 70KB/s, but now yields a more respectable 540KB/s.

### Note about Quagga
Most existing scripts utilising Quagga assume that `bgpd` and `zebra` exist within `/usr/lib/quagga/` which is where Ubuntu 14.04 installs them, but the packages on Ubuntu 20.04 install to `/usr/sbin/`. This is accounted for in this repository.