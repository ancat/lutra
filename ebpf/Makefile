#LINUX_HEADERS=$(shell rpm -ql kernel-devel | head -1)
LINUX_HEADERS=$(shell rpm -ql kernel-devel | head -1)
CFLAGS=$(CFLAGS)

all:
	clang $(CFLAGS) -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wall \
        -I $(LINUX_HEADERS)/include/linux \
        -I $(LINUX_HEADERS)/arch/x86/include \
        -I $(LINUX_HEADERS)/arch/x86/include/generated \
        -I $(LINUX_HEADERS)/include \
        -I $(LINUX_HEADERS)/include/generated/uapi \
        -I $(LINUX_HEADERS)/arch/x86/include/uapi \
        -I $(LINUX_HEADERS)/include/uapi \
		-O2 -emit-llvm -c /dist/watcher.c \
		-o - | llc -march=bpf -filetype=obj -o "/dist/watcher.o"
