obj-y += mcheck/
obj-y += microcode/
obj-y += mtrr/

obj-$(CONFIG_AMD) += amd.o
obj-$(CONFIG_CENTAUR) += centaur.o
obj-y += common.o
obj-$(CONFIG_HYGON) += hygon.o
obj-$(CONFIG_INTEL) += intel.o
obj-$(CONFIG_INTEL) += intel_cacheinfo.o
obj-$(CONFIG_INTEL) += mwait-idle.o
obj-$(CONFIG_SHANGHAI) += shanghai.o

vpmu-y := vpmu.o
vpmu-$(CONFIG_AMD) += vpmu_amd.o
vpmu-$(CONFIG_INTEL) += vpmu_intel.o
obj-$(CONFIG_VPMU) += $(vpmu-y)
