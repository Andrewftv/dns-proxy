# AdCleaner

DNS resolution is handled by dns.google (8.8.8.8) via DNS over HTTPS. Block all ad providers from the following [list](https://raw.githubusercontent.com/ph00lt0/blocklists/master/blocklist.txt)

Port 8080 is used for the web management

## Version build instructions.
The build process is performed on a Linux machine (Windows is untested). Alternatively, you can build directly on the target Raspberry Pi server. This eliminates the need for Docker and a cross-platform GCC toolchain. A corresponding GCC toolchain is required to build a cross-platform version. When building the ARM_v7 image, I used arm-unknown-linux-musleabi to minimize the Docker image size and reduce the number of dependencies. I used [crosstool-ng](https://crosstool-ng.github.io/) to build it. You can use the standard armv8-rpi4-linux-gnueabihf toolchain for Raspberry Pi, but the resulting image size will exceed 100MB.

### Build on target Linux machine:
```
cargo build --release
```
### Build on host Linux machine for ARM v7(raspberry pi 32 bits)
```
cargo build --release --target=armv7-unknown-linux-musleabihf
```
### Create docker image on host machine for ARM v7(raspberry pi 32 bits)
```
docker build -f Dockerfile.arm_v7 --platform linux/arm/v7 -t dns-proxy:arm_v7 .
```
### Export docker image from host machine
```
docker save -o dns-proxy.tar dns-proxy:arm_v7
```
### Install docker image on target machine
```
docker load -i dns-proxy.tar
```
### Run docker container on target machine(raspberry pi 32 bits)
For single run
```
docker run --rm -p 53:53/udp -p 8080:8080 dns-proxy:arm_v7
```
Run as deamon
```
docker run -d --restart=unless-stopped -p 53:53/udp -p 8080:8080 dns-proxy:arm_v7
```
