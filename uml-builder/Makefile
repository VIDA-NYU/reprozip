KERNEL_VERSION ?=	4.0.2
DOCKER_IMAGE ?=		moul/kernel-builder:stable
TARGET ?=		./dist/linux

CONCURRENCY_LEVEL ?=	$(shell grep -m1 cpu\ cores /proc/cpuinfo 2>/dev/null | sed 's/[^0-9]//g' | grep '[0-9]' || sysctl hw.ncpu | sed 's/[^0-9]//g' | grep '[0-9]')
ARCH ?=			um
ENTER_COMMAND ?=	(git show-ref --tags | egrep -q "refs/tags/v$(KERNEL_VERSION)$$" || git fetch --tags) && git checkout v$(KERNEL_VERSION) && git log HEAD^..HEAD
DOCKER_VOLUMES ?=	-v $(PWD)/.config:/tmp/.config \
			-v $(PWD)/ccache:/ccache/ \
			-v $(PWD)/dist:/usr/src/linux/build/ \
			-v $(PWD)/patch.sh:/usr/src/linux/patch.sh:ro \
			-v $(PWD)/patches:/usr/src/linux/patches
DOCKER_ENV ?=		-e CONCURRENCY_LEVEL=$(CONCURRENCY_LEVEL) \
			-e LOCALVERSION_AUTO=no \
			-e ARCH=$(ARCH)
DOCKER_RUN_OPTS ?=	-it --rm
DOCKER_BIN ?=		docker


all: build


.PHONY: shell
shell::
	$(DOCKER_BIN) run $(DOCKER_RUN_OPTS) $(DOCKER_ENV) $(DOCKER_VOLUMES) $(DOCKER_IMAGE) \
		/bin/bash -xec ' \
			$(ENTER_COMMAND) && \
			cp /tmp/.config .config && \
			/bin/bash -xe patch.sh && \
			bash ; \
			cp .config /tmp/.config \
		'


.PHONY: run
run::	$(TARGET)
	$(TARGET) \
		mem=2G \
		rootfstype=hostfs \
		eth0=slirp,,/usr/bin/slirp-fullbolt \
		rw \
		init=/bin/bash


.PHONY: defconfig oldconfig olddefconfig menuconfig
defconfig oldconfig olddefconfig menuconfig::
	$(DOCKER_BIN) run $(DOCKER_RUN_OPTS) $(DOCKER_ENV) $(DOCKER_VOLUMES) $(DOCKER_IMAGE) \
		/bin/bash -xec ' \
			$(ENTER_COMMAND) && \
			cp /tmp/.config .config && \
			/bin/bash -xe patch.sh && \
			make $@ && \
			cp .config /tmp/.config \
		'


.PHONY: build
build:: $(TARGET)


$(TARGET): .config
	$(DOCKER_BIN) run $(DOCKER_RUN_OPTS) $(DOCKER_ENV) $(DOCKER_VOLUMES) $(DOCKER_IMAGE) \
		/bin/bash -xec ' \
			$(ENTER_COMMAND) && \
			cp /tmp/.config .config && \
			/bin/bash -xe patch.sh && \
			make -j $(CONCURRENCY_LEVEL) linux && \
			strip linux && \
			cp linux build/ \
		'


.PHONY: dist
dist:: $(TARGET)
	$(MAKE) dist_do || $(MAKE) dist_teardown


.PHONY: dist_do
dist_do:
	git branch -D dist || true
	git checkout --orphan dist
	cp $(TARGET) ../linux
	git add -f ../linux
	git commit ../linux -m "Dist"
	git push -u origin dist -f
	$(MAKE) dist_teardown


.PHONY: dist_teardown
dist_teardown:
	git checkout master

