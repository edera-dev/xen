XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-iommu

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM) iommu.c list.h *.tmp

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
# Only the functions under test are taken from iommu.c, since the rest of it
# is the IOMMU core, which these tests do not build.
iommu.c: $(XEN_ROOT)/xen/drivers/passthrough/iommu.c
	{ echo '#include "harness.h"'; \
	  sed -n -e '/^int iommu_domain_pviommu_init(/,/^}/p' \
	         -e '/^int cf_check iommu_context_teardown(/,/^}/p' <$<; } >$@.tmp
	mv -f $@.tmp $@

list.h: $(XEN_ROOT)/xen/include/xen/list.h
	sed -e '/#include/d' <$< >$@.tmp
	mv -f $@.tmp $@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)
LDFLAGS += $(APPEND_LDFLAGS)

iommu.o test-iommu.o: harness.h list.h
test-iommu: iommu.o test-iommu.o
	$(CC) $^ -o $@ $(LDFLAGS)

-include $(DEPS_INCLUDE)
