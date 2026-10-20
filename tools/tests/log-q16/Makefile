XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-log-q16

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM) log-q16.c

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

log-q16.c: $(XEN_ROOT)/xen/lib/log-q16.c
	# Remove includes and add the test harness header
	sed -e '/#include/d' -e '1s/^/#include "harness.h"/' <$< >$@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)
LDFLAGS += $(APPEND_LDFLAGS)

test-log-q16.o log-q16.o: harness.h

test-log-q16: log-q16.o test-log-q16.o
	$(CC) $^ -o $@ $(LDFLAGS) -lm

-include $(DEPS_INCLUDE)
