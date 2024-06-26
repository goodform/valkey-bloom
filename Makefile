DEBUGFLAGS = -g -ggdb -O2
ifeq ($(DEBUG), 1)
	DEBUGFLAGS = -g -ggdb -O0
endif

# find the OS
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
CPPFLAGS =  -Wall -Wno-unused-function $(DEBUGFLAGS) -fPIC -std=gnu99 -D_GNU_SOURCE
CC:=$(shell sh -c 'type $(CC) >/dev/null 2>/dev/null && echo $(CC) || echo gcc')

# Compile flags for linux / osx
ifeq ($(uname_S),Linux)
	SHOBJ_CFLAGS ?=  -fno-common -g -ggdb
	SHOBJ_LDFLAGS ?= -shared -Bsymbolic -Bsymbolic-functions
else
	CFLAGS += -mmacosx-version-min=10.6
	SHOBJ_CFLAGS ?= -dynamic -fno-common -g -ggdb
	SHOBJ_LDFLAGS ?= -dylib -exported_symbol _ValkeyModule_OnLoad -macosx_version_min 10.6
endif

ROOT=$(shell pwd)
# Flags for preprocessor
LDFLAGS = -lm -lc

CPPFLAGS += -I$(ROOT) -I$(ROOT)/contrib
SRCDIR := $(ROOT)/src
MODULE_OBJ = $(SRCDIR)/valkeybloom.o
MODULE_SO = $(ROOT)/valkeybloom.so

DEPS = $(ROOT)/contrib/MurmurHash2.o \
	   $(SRCDIR)/sb.o \
	   $(SRCDIR)/cf.o

export

all: $(MODULE_SO)

$(MODULE_SO): $(MODULE_OBJ) $(DEPS)
	$(LD) $^ -o $@ $(SHOBJ_LDFLAGS) $(LDFLAGS)

build: all
	$(MAKE) -C tests build-test

test: $(MODULE_SO)
	$(MAKE) -C tests test

build-test: $(MODULE_SO)
	$(MAKE) -C tests build-test

perf:
	$(MAKE) -C tests perf


clean:
	$(RM) $(MODULE_OBJ) $(MODULE_SO) $(DEPS)
	$(RM) -f print_version
	$(RM) -rf build
	$(MAKE) -C tests clean

distclean: clean

docker:
	docker build -t valkey/valkeybloom .

docker_push: docker
	docker push valkey/valkeybloom:latest

# Compile an executable that prints the current version
print_version:  $(SRCDIR)/version.h $(SRCDIR)/print_version.c
	@$(CC) -o $@ -DPRINT_VERSION_TARGET $(SRCDIR)/$@.c
