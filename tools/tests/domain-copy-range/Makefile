XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-domain-copy-range

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM) memory.c *.tmp

.PHONY: distclean
distclean: clean
	$(RM) -- *~

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC)/tests
	$(INSTALL_PROG) $(TARGET) $(DESTDIR)$(LIBEXEC)/tests

.PHONY: uninstall
uninstall:
	$(RM) -- $(addprefix $(DESTDIR)$(LIBEXEC)/tests/,$(TARGET))

# Generated files are written under a temporary name and then renamed, so an
# interrupted build cannot leave a partial file that make takes as current.
# Only the XENMEM_domain_copy_range handler is taken from memory.c, made
# non-static so the test can call it.
memory.c: $(XEN_ROOT)/xen/common/memory.c
	{ echo '#include "harness.h"'; \
	  sed -n -e '/^#define COPY_RANGE_ERRS_BATCH /p' \
	         -e '/^static int flush_copy_range_errs(/,/^}/p' \
	         -e '/^static bool copy_range_buffer_readable(/,/^}/p' \
	         -e '/^static int domain_copy_range(/,/^}/{s/^static //;p;}' <$<; \
	} >$@.tmp
	mv -f $@.tmp $@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)
LDFLAGS += $(APPEND_LDFLAGS)

memory.o test-domain-copy-range.o: harness.h
test-domain-copy-range: memory.o test-domain-copy-range.o
	$(CC) $^ -o $@ $(LDFLAGS)

-include $(DEPS_INCLUDE)
