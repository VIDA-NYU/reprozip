KERNEL_VERSION ?=	4.0.2
DOCKER_IMAGE ?=		moul/kernel-builder:stable

CONCURRENCY_LEVEL ?=	$(shell grep -m1 cpu\ cores /proc/cpuinfo 2>/dev/null | sed 's/[^0-9]//g' | grep '[0-9]' || sysctl hw.ncpu | sed 's/[^0-9]//g' | grep '[0-9]')
ARCH ?=			um
ENTER_COMMAND ?=	(git show-ref --tags | egrep -q "refs/tags/v$(KERNEL_VERSION)$$" || git fetch --tags) && git checkout v$(KERNEL_VERSION) && git log HEAD^..HEAD
DOCKER_VOLUMES ?=	-v $(PWD)/.config:/tmp/.config \
			-v $(PWD)/ccache:/ccache/ \
			-v $(PWD)/dist:/usr/src/linux/build/
DOCKER_ENV ?=		-e CONCURRENCY_LEVEL=$(CONCURRENCY_LEVEL) \
			-e LOCALVERSION_AUTO=no \
			-e ARCH=$(ARCH)
DOCKER_RUN_OPTS ?=	-it --rm
DOCKER_BIN ?=		docker


all: build


shell::
	$(DOCKER_BIN) run $(DOCKER_RUN_OPTS) $(DOCKER_ENV) $(DOCKER_VOLUMES) $(DOCKER_IMAGE) \
		/bin/bash -xec ' \
			$(ENTER_COMMAND) && \
			cp /tmp/.config .config && \
			bash ; \
			cp .config /tmp/.config \
		'


defconfig oldconfig olddefconfig menuconfig::
	$(DOCKER_BIN) run $(DOCKER_RUN_OPTS) $(DOCKER_ENV) $(DOCKER_VOLUMES) $(DOCKER_IMAGE) \
		/bin/bash -xec ' \
			$(ENTER_COMMAND) && \
			cp /tmp/.config .config && \
			make $@ && \
			cp .config /tmp/.config \
		'


build::
	$(DOCKER_BIN) run $(DOCKER_RUN_OPTS) $(DOCKER_ENV) $(DOCKER_VOLUMES) $(DOCKER_IMAGE) \
		/bin/bash -xec ' \
			$(ENTER_COMMAND) && \
			cp /tmp/.config .config && \
			make -j $(CONCURRENCY_LEVEL) linux && \
			cp linux build/ && \
			cp .config /tmp/.config \
		'
