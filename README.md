# AdCleaner

DNS resolution is handled by dns.google (8.8.8.8) via DNS over HTTPS. Block all ad providers from the following [list](https://raw.githubusercontent.com/ph00lt0/blocklists/master/blocklist.txt)

Port 8080 is used for the web management

## Version build instructions.
The build process is performed on a Linux machine (Windows is untested). Alternatively, you can build directly on the target Raspberry Pi server. This eliminates the need for Docker and a cross-platform GCC toolchain. A corresponding GCC toolchain is required to build a cross-platform version. When building the ARM_v7 image, I used <ins>arm-unknown-linux-musleabi</ins> toolchain to minimize the Docker image size and reduce the number of dependencies. I used [crosstool-ng](https://crosstool-ng.github.io/) to build it. You can use the standard <ins>armv8-rpi4-linux-gnueabihf</ins> toolchain for Raspberry Pi, but the resulting image size will exceed 100MB. When building the AARCH64 image, I used <ins>aarch64-unknown-linux-musl</ins> toolchain.

### Build on target Linux machine:
```
cargo build --release
```
### Build on host Linux machine for ARM v7 or AARCH64
```
cargo build --release --target=armv7-unknown-linux-musleabihf
```
```
cargo build --release --target=aarch64-unknown-linux-musl
```
### Create docker image on host machine for ARM v7 or AARCH64
```
docker build -f Dockerfile.arm_v7 --no-cache --platform linux/arm/v7 -t dns-proxy:arm_v7 .
```
```
docker build -f Dockerfile.aarch64 --no-cache --platform linux/arm64 -t dns-proxy:aarch64 .
```
### Export docker image from host machine
```
docker save -o dns-proxy-arm_v7.tar dns-proxy:arm_v7
```
```
docker save -o dns-proxy-aarch64.tar dns-proxy:aarch64
```
### Install docker image on target machine
```
docker load -i dns-proxy-arm_v7.tar
```
```
docker load -i dns-proxy-aarch64.tar
```
### Run docker container on target machine
For single run
```
docker run --rm -p 53:53/udp -p 8080:8080 dns-proxy:arm_v7
```
```
docker run --rm -p 53:53/udp -p 8080:8080 dns-proxy:aarch64
```
Run as deamon
```
docker run -d --restart=unless-stopped -p 53:53/udp -p 8080:8080 dns-proxy:arm_v7
```
```
docker run -d --restart=unless-stopped -p 53:53/udp -p 8080:8080 dns-proxy:aarch64
```
