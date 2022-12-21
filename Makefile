# List of subdirectories. Not used for build, but cleanup!
SUBDIRS := 	.cargo               \
		libedge              \
		libedge/src          \
		libeapp              \
		libeapp/.cargo       \
		libeapp/macros       \
		libeapp/macros/src   \
		libeapp/src          \
		libeapp/src/internal \
		libhapp              \
		libhapp/.cargo       \
		libhapp/src          \
		libhapp/src/internal \

# Target architecture for the host application libraries
TARGET_ARCH := riscv64gc-unknown-linux-gnu
x86_64: TARGET_ARCH := x86_64-unknown-linux-gnu

# Common build options. Always build for release to minimize binary size!
CARGO_FLAGS       := -v --release
CARGO_DEBUG_FLAGS := --features debug_memory

dir2tgt = $(patsubst %, ./%/$(strip $(2)),$(strip $(1)))

all: riscv64

riscv64:
	cargo build --target $(TARGET_ARCH) $(CARGO_FLAGS)

# This target builds the host application libraries for x86_64 architecture.
# Enclave application libraries will still be built for the RISC-V target.
x86_64:
	cargo build --target $(TARGET_ARCH) $(CARGO_FLAGS)

# Build with SDK's internal enclave memory debugging support
debug:
	cargo build --target $(TARGET_ARCH) $(CARGO_DEBUG_FLAGS) $(CARGO_FLAGS)

# Clean build and temporary files:
clean:
	cargo clean
	rm -f *~ $(call dir2tgt, $(strip $(SUBDIRS)), *~)
