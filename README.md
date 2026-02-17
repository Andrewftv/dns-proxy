# AdCleaner

DNS resolution is handled by dns.google (8.8.8.8) via DNS over HTTPS. Block all ad providers from the following [list](https://raw.githubusercontent.com/ph00lt0/blocklists/master/blocklist.txt)

Port 8080 is used for the web management

## Build for x86_64:
- cargo build --release

## Build for arm v7(raspberry pi 32 bits)
- cargo build --release --target=armv7-unknown-linux-musleabihf

## Create docker image(raspberry pi 32 bits)
- docker build -f Dockerfile.arm_v7 --platform linux/arm/v7 -t dns-proxy:arm_v7 .

## Run docker container(raspberry pi 32 bits)
For single run
- docker run --rm -p 53:53/udp -p 8080:8080 dns-proxy:arm_v7

Run as deamon
- docker run -d --restart=unless-stopped -p 53:53/udp -p 8080:8080 dns-proxy:arm_v7
