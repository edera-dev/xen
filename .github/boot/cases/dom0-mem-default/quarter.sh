# Without dom0_mem, Xen gives dom0 a quarter of the host's memory. On a 6G
# host that is more than the 1G floor and less than the 4G ceiling.
xen_options=${xen_options/ dom0_mem=1G/}
memory_mib=6144

expect+=('^\(XEN\) No dom0_mem, using [0-9]+ MiB of the host.s [0-9]+ MiB$')

check() {
    local dom0 host
    read -r dom0 host < <(sed -n 's/^(XEN) No dom0_mem, using \([0-9]*\) MiB of the host.s \([0-9]*\) MiB$/\1 \2/p' "$1")
    [ "${dom0:-0}" -eq $((${host:-0} / 4)) ] ||
        echo "dom0 has $dom0 MiB of the host's $host MiB, not a quarter"
}
