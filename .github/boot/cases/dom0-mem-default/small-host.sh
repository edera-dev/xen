# Without dom0_mem, Xen gives dom0 no less than 1G, unless that would leave
# Xen less than a quarter of the host. On a 1G host, dom0 gets three
# quarters.
xen_options=${xen_options/ dom0_mem=1G/}
memory_mib=1024

expect+=('^\(XEN\) No dom0_mem, using [0-9]+ MiB of the host.s [0-9]+ MiB$')

check() {
    local dom0 host
    read -r dom0 host < <(sed -n 's/^(XEN) No dom0_mem, using \([0-9]*\) MiB of the host.s \([0-9]*\) MiB$/\1 \2/p' "$1")
    # The log rounds both sizes down to whole MiB, which moves three
    # quarters by up to one.
    [ $((4 * ${dom0:-0})) -ge $((3 * ${host:-0} - 3)) ] &&
        [ $((4 * ${dom0:-0})) -le $((3 * ${host:-0} + 3)) ] ||
        echo "dom0 has $dom0 MiB of the host's $host MiB, not three quarters"
}
