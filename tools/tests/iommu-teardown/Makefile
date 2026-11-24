XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-iommu-teardown

GENERATED := vtd.c amd.c amd-cmd.c x86.c identity_map.h list.h

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM) $(GENERATED) *.tmp

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

# The functions under test are taken from the hypervisor sources as they
# are, with static dropped so the test can call them. Generated files are
# written under a temporary name and then renamed, so an interrupted build
# cannot leave a partial file that make takes as current.
vtd.c: $(XEN_ROOT)/xen/drivers/passthrough/vtd/iommu.c
	{ echo '#include "harness.h"'; \
	  sed -n -e '/^static void intel_iommu_free_dids(/,/^}/{s/^static //;p;}' \
	         -e '/^static int __must_check cf_check iommu_flush_iotlb(/,/^}/{s/^static //;p;}' \
	         -e '/^static int cf_check intel_iommu_context_init(/,/^}/{s/^static //;p;}' \
	         -e '/^static void cf_check iommu_domain_teardown(/,/^}/{s/^static //;p;}' <$<; \
	} >$@.tmp
	mv -f $@.tmp $@

amd.c: $(XEN_ROOT)/xen/drivers/passthrough/amd/pci_amd_iommu.c
	{ echo '#include "harness.h"'; \
	  sed -n -e '/^static void amd_iommu_free_dids(/,/^}/{s/^static //;p;}' \
	         -e '/^static int cf_check amd_iommu_context_init(/,/^}/{s/^static //;p;}' \
	         -e '/^static void cf_check amd_iommu_domain_destroy(/,/^}/{s/^static //;p;}' <$<; \
	} >$@.tmp
	mv -f $@.tmp $@

amd-cmd.c: $(XEN_ROOT)/xen/drivers/passthrough/amd/iommu_cmd.c
	{ echo '#include "harness.h"'; \
	  sed -n -e '/^static void _amd_iommu_flush_pages(/,/^}/{s/^static //;p;}' <$<; \
	} >$@.tmp
	mv -f $@.tmp $@

x86.c: $(XEN_ROOT)/xen/drivers/passthrough/x86/iommu.c
	{ echo '#include "harness.h"'; \
	  sed -n -e '/^int arch_iommu_context_init(/,/^}/p' \
	         -e '/^void iommu_identity_map_teardown(/,/^}/p' <$<; \
	} >$@.tmp
	mv -f $@.tmp $@

identity_map.h: $(XEN_ROOT)/xen/drivers/passthrough/x86/iommu.c
	sed -n -e '/^struct identity_map {/,/^};/p' <$< >$@.tmp
	mv -f $@.tmp $@

list.h: $(XEN_ROOT)/xen/include/xen/list.h
	sed -e '/#include/d' <$< >$@.tmp
	mv -f $@.tmp $@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)
LDFLAGS += $(APPEND_LDFLAGS)

OBJS := vtd.o amd.o amd-cmd.o x86.o test-iommu-teardown.o

$(OBJS): harness.h identity_map.h list.h
$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

-include $(DEPS_INCLUDE)
