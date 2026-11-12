# Without dom0_mem, Xen gives dom0 a quarter of the host's memory, but no less
# than 1G. A quarter of a 2G host is less, so dom0 gets 1G.
xen_options=${xen_options/ dom0_mem=1G/}
memory_mib=2048

expect+=('^\(XEN\) No dom0_mem, using 1024 MiB of the host.s [0-9]+ MiB$')
