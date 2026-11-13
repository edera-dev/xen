# With pci-passthrough=on, Xen registers the host bridge that the MCFG
# describes, and dom0 reports each PCI device to Xen. The build has no SMMUv3
# driver, so the IOMMU is off and dom0 gets no vPCI.
expect+=(
    '^\(XEN\) PCI: segment 0000 ECAM at '
    '^\(XEN\) PCI add device '
)

# dom0 logs each device that Xen refuses. Xen registers the bridge even when it
# cannot read the bridge's windows from the DSDT, and only warns.
check() {
    grep -E 'Failed to add - passthrough|no usable _CRS' "$1"
}
