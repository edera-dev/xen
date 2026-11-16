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
	$(RM) -- *.o $(TARGET) $(DEPS_RM) pviommu-init.c *.tmp

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
# Only iommu_domain_pviommu_init() is taken: the rest of iommu.c is the IOMMU
# core, which these tests do not build.
pviommu-init.c: $(XEN_ROOT)/xen/drivers/passthrough/iommu.c
	{ echo '#include "harness.h"'; \
	  sed -n '/^int iommu_domain_pviommu_init(/,/^}/p' <$<; } >$@.tmp
	mv -f $@.tmp $@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)
LDFLAGS += $(APPEND_LDFLAGS)

pviommu-init.o test-iommu.o: harness.h
test-iommu: pviommu-init.o test-iommu.o
	$(CC) $^ -o $@ $(LDFLAGS)

-include $(DEPS_INCLUDE)
