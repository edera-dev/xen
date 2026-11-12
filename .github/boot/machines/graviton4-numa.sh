# Graviton4 with two sockets, each its own NUMA node.
# shellcheck source=/dev/null
. "$HERE/machines/graviton4.sh"
sockets=2

expect+=('smp: Brought up 2 nodes, ')
