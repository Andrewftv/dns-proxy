# AdCleaner

The DNS server resolve names by dns.google (8.8.8.8) by DNS over HTTPS protocol.
Block all advertisement providers from this [list](https://raw.githubusercontent.com/ph00lt0/blocklists/master/blocklist.txt)

Port 8080 is used for the web management

## Build for x86_64:
**cargo build --release**

## Build for arm v7(raspberri pi 32 bits)
**cargo build --release --target=armv7-unknown-linux-musleabihf**

## Create docker image(raspberri pi 32 bits)
**docker build -f Dockerfile.arm_v7 --platform linux/arm/v7 -t dns-proxy:arm_v7 .**

## Run docker container(raspberri pi 32 bits)
**docker run --rm -p 53:53/udp -p 8080:8080 dns-proxy:arm_v7** for single run

**docker run -d --restart=unless-stopped -p 53:53/udp -p 8080:8080 dns-proxy:arm_v7** run as deamon