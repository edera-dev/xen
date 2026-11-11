XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += domid
SUBDIRS-y += log-q16
SUBDIRS-y += mem-claim
SUBDIRS-y += numa
SUBDIRS-y += paging-mempool
SUBDIRS-y += pdx
SUBDIRS-y += rangeset
SUBDIRS-y += resource
SUBDIRS-y += vpci
SUBDIRS-y += xenstore

# The Arm ACPI tests build code that runs only in a 64-bit hypervisor, so they
# build only on 64-bit hosts: the DSDT walker's windows need a 64-bit unsigned
# long.  The DSDT tables are compiled by iasl, which configure requires only on
# the hosts that build ACPI tables.
ARM_ACPI_TESTS := iort
ifneq ($(IASL),)
ARM_ACPI_TESTS += dsdt
endif
SUBDIRS-$(CONFIG_X86_64) += $(ARM_ACPI_TESTS)
SUBDIRS-$(CONFIG_ARM_64) += $(ARM_ACPI_TESTS)

SUBDIRS-$(CONFIG_X86) += cpu-policy
SUBDIRS-$(CONFIG_X86) += tsx
ifneq ($(clang),y)
SUBDIRS-$(CONFIG_X86) += x86_emulator
endif

.PHONY: all clean install distclean uninstall
all clean distclean install uninstall: %: subdirs-%
