obj-y += hap.o
obj-y += guest_walk_2.o
obj-y += guest_walk_3.o
obj-y += guest_walk_4.o

nested-y := nested_hap.o
nested-$(CONFIG_INTEL_VMX) += nested_ept.o
obj-$(CONFIG_NESTED_VIRT) += $(nested-y)
