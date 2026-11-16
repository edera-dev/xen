XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-pci-sbdf

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM) pci-sbdf.h *.tmp

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
# Only the PCI_* macros and pci_sbdf_t are taken from pci.h.
pci-sbdf.h: $(XEN_ROOT)/xen/include/xen/pci.h
	{ sed -n '/^#define PCI_SEG(/,/^#define PCI_SBDF(/p' <$<; \
	  sed -n '/^typedef union {/,/^} pci_sbdf_t;/p' <$<; } >$@.tmp
	mv -f $@.tmp $@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)
# Trap on a shift whose result does not fit its type, rather than going on.
CFLAGS += -fsanitize=shift -fsanitize-undefined-trap-on-error
LDFLAGS += $(APPEND_LDFLAGS)

test-pci-sbdf.o: harness.h pci-sbdf.h
test-pci-sbdf: test-pci-sbdf.o
	$(CC) $^ -o $@ $(LDFLAGS)

-include $(DEPS_INCLUDE)
