DOCKER := docker
CARGO := cargo
IMAGE_NAME := dns-proxy
# Default build
all: aarch64

aarch64:
	@echo "[*** Build AARCH64 version]"
	@rm -f $(IMAGE_NAME)-$@.tar
	@$(CARGO) clean --release --target=aarch64-unknown-linux-musl
	@$(CARGO) build --release --target=aarch64-unknown-linux-musl
	@echo "[*** Delete previsional image]"
	@$(DOCKER) rmi -f $(IMAGE_NAME):$@
#	@echo "[*** Run AARCH64 emulator]"
#	@$(DOCKER) run --privileged --rm tonistiigi/binfmt --install arm64
	@echo "[*** Create docker image]"
	@$(DOCKER) build -f Dockerfile.$@ --no-cache --platform linux/arm64 -t $(IMAGE_NAME):$@ .
	@echo "[*** Create export tar]"
	@$(DOCKER) save -o $(IMAGE_NAME)-$@.tar $(IMAGE_NAME):$@
arm_v7:
	@echo "[*** Build ARM V7 version]"
	@rm -f $(IMAGE_NAME)-$@.tar
	@$(CARGO) clean --release --target=armv7-unknown-linux-musleabihf
	@$(CARGO) build --release --target=armv7-unknown-linux-musleabihf
	@echo "[*** Delete previsional image]"
	@$(DOCKER) rmi -f $(IMAGE_NAME):$@
	@echo "[*** Create docker image]"
	@$(DOCKER) build -f Dockerfile.$@ --no-cache --platform linux/arm/v7 -t $(IMAGE_NAME):$@ .
	@echo "[*** Create export tar]"
	@$(DOCKER) save -o $(IMAGE_NAME)-$@.tar $(IMAGE_NAME):$@
x86_64:
	@echo "Not supported yet"
clean:
	@echo "[*** Clean all]"
	@$(CARGO) clean
