XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-spcr

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM) spcr.c pci_regs.h *.tmp

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
spcr.c: $(XEN_ROOT)/xen/arch/arm/acpi/spcr.c
	# Remove includes and add the test harness header
	sed -e '/#include/d' -e '1s/^/#include "harness.h"/' <$< >$@.tmp
	mv -f $@.tmp $@

pci_regs.h: $(XEN_ROOT)/xen/include/xen/pci_regs.h
	sed -e '/#include/d' <$< >$@.tmp
	mv -f $@.tmp $@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)
LDFLAGS += $(APPEND_LDFLAGS)

spcr.o: harness.h pci_regs.h
test-spcr.o: harness.h pci_regs.h
test-spcr: spcr.o test-spcr.o
	$(CC) $^ -o $@ $(LDFLAGS)

-include $(DEPS_INCLUDE)
