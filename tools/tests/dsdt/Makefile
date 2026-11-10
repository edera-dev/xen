XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-dsdt
TABLES := bridges.h virt.h

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM) dsdt.c $(TABLES) *.aml *.hex *.tmp

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
dsdt.c: $(XEN_ROOT)/xen/arch/arm/acpi/dsdt.c
	# Remove includes and add the test harness header
	sed -e '/#include/d' -e '1s/^/#include "harness.h"/' <$< >$@.tmp
	mv -f $@.tmp $@

# Each table becomes an array named after its file, as in tools/libacpi.  The
# tables copy firmware, and iasl remarks on what firmware does (a _SRS with no
# _DIS, a Package shorter than declared), so remarks are off.
%.h: %.asl
	$(IASL) -vs -vr -p $* -tc $<
	sed -e 's/AmlCode/$*/g' -e 's/_aml_code//g' $*.hex >$@.tmp
	$(RM) -- $*.aml $*.hex
	mv -f $@.tmp $@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)
LDFLAGS += $(APPEND_LDFLAGS)

dsdt.o: harness.h
test-dsdt.o: harness.h $(TABLES)
test-dsdt: dsdt.o test-dsdt.o
	$(CC) $^ -o $@ $(LDFLAGS)

-include $(DEPS_INCLUDE)
