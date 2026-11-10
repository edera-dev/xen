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

# The walker runs only in a 64-bit hypervisor, and its windows need a 64-bit
# unsigned long.  Its tables are compiled by iasl, which configure requires
# only on the hosts that build ACPI tables.
ifneq ($(IASL),)
SUBDIRS-$(CONFIG_X86_64) += dsdt
SUBDIRS-$(CONFIG_ARM_64) += dsdt
endif

SUBDIRS-$(CONFIG_X86) += cpu-policy
SUBDIRS-$(CONFIG_X86) += tsx
ifneq ($(clang),y)
SUBDIRS-$(CONFIG_X86) += x86_emulator
endif

.PHONY: all clean install distclean uninstall
all clean distclean install uninstall: %: subdirs-%
