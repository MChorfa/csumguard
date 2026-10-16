EGRESS_MTU ?= 1500
CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
MULTIARCH ?= $(shell $(CC) -dumpmachine)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CFLAGS := -O2 -g -Wall -Wextra -Werror -fstack-protector-strong -std=c11
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -include build/policy-config.h -I/usr/include/$(MULTIARCH) -Wall -Werror
.PHONY: all detector test clean FORCE
all: build/csumguard_tc.bpf.o build/csumguard_loader build/csumguard_launch build/send_frame
build:
	mkdir -p $@
# Configuration changes must invalidate prior objects even without source edits.
FORCE:
build/policy-config.h: FORCE | build
	printf '%s\n' '#define EGRESS_MTU $(EGRESS_MTU)' > $@.tmp
	cmp -s $@.tmp $@ || mv $@.tmp $@
	rm -f $@.tmp
build/csumguard_tc.bpf.o: csumguard_tc.bpf.c policy.h Makefile build/policy-config.h | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
build/csumguard_loader: loader.c policy.h Makefile | build
	$(CC) $(CFLAGS) -D_GNU_SOURCE $< -o $@ -lbpf -lelf -lz -lcrypto
build/csumguard_launch: launch.c launch_policy.h Makefile | build
	$(CC) $(CFLAGS) -D_GNU_SOURCE $< -o $@ -lpthread
build/send_frame: tests/send_frame.c policy.h Makefile build/policy-config.h | build
	$(CC) $(CFLAGS) -D_GNU_SOURCE -include build/policy-config.h $< -o $@
# Generate against the target host BTF; do not ship a guessed sk_buff layout.
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp && test -s $@.tmp && mv $@.tmp $@ || { rm -f $@.tmp; exit 1; }
detector: build/csumguard_detect.bpf.o
build/csumguard_detect.bpf.o: csumguard_detect.bpf.c detect_policy.h vmlinux.h Makefile | build
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I. -Wall -Werror -c $< -o $@
build/test_policy: tests/test_policy.c tests/legacy_tc_body.h policy.h detect_policy.h Makefile build/policy-config.h | build
	$(CC) $(CFLAGS) -include build/policy-config.h $< -o $@
build/test_launch: tests/test_launch.c launch.c launch_policy.h Makefile | build
	$(CC) $(CFLAGS) -D_GNU_SOURCE $< -o $@ -lpthread
test: build/test_policy build/test_launch build/send_frame build/csumguard_launch
	./build/test_policy
	./build/test_launch
	./build/send_frame --self-test
clean:
	rm -rf build
	rm -f vmlinux.h vmlinux.h.tmp
