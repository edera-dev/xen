# Graviton3: Neoverse V1 cores.
cpu=neoverse-v1

# The branch history sequence Xen runs on exception entry for this core, the
# one Linux runs for it.
expect+=('^\(XEN\) CPU0 will use 32 loops workaround on exception entry')
