# pci-scan gives dom0 a PCI bus that Xen emulates, which Xen can describe
# only in a device tree. With ACPI, Xen ignores the option, and dom0 reports
# its devices to Xen as it does without the option. Xen logs each device that
# dom0 reports. If Xen skipped only its scan, it would drop those reports and
# log none.
xen_options+=' pci-scan=1'

expect+=(
    '^\(XEN\) PCI: pci-scan is not supported with ACPI, ignoring it$'
    '^\(XEN\) PCI add device '
)
