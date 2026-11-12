# Graviton4: Neoverse V2 cores.
#
# QEMU has no Neoverse V2. Neoverse N2 is a core of the same generation,
# Armv9.0 with 128-bit SVE, and a Neoverse V2 MIDR (r0p1) makes Xen and dom0
# take it for one, so they apply the errata of a V2.
cpu=neoverse-n2,midr=0x410fd4f1

# The branch history sequence Xen runs on exception entry for this core, the
# one Linux runs for it.
expect+=('^\(XEN\) CPU0 will use 132 loops workaround on exception entry')
