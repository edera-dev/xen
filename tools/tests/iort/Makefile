XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-iort

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM) iort.c *.tmp

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

# Written under a temporary name and then renamed, so an interrupted build
# cannot leave a partial file that make takes as current.
iort.c: $(XEN_ROOT)/xen/arch/arm/acpi/iort.c
	# Remove includes and add the test harness header
	sed -e '/#include/d' -e '1s/^/#include "harness.h"/' <$< >$@.tmp
	mv -f $@.tmp $@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)
LDFLAGS += $(APPEND_LDFLAGS)

# The test includes iort.c, so that it can drop the previous case's table.
test-iort.o: harness.h iort.c
test-iort: test-iort.o
	$(CC) $^ -o $@ $(LDFLAGS)

-include $(DEPS_INCLUDE)
