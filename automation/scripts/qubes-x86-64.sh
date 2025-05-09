#!/bin/sh

set -ex

# One of:
#  - ""             PV dom0,  PVH domU
#  - dom0pvh        PVH dom0, PVH domU
#  - dom0pvh-hvm    PVH dom0, HVM domU
#  - pci-hvm        PV dom0,  HVM domU + PCI Passthrough
#  - pci-pv         PV dom0,  PV domU + PCI Passthrough
#  - pvshim         PV dom0,  PVSHIM domU
#  - s3             PV dom0,  S3 suspend/resume
#  - tools-tests-pv PV dom0, run tests from tools/tests/*
#  - tools-tests-pvh PVH dom0, run tests from tools/tests/*
test_variant=$1

### defaults
extra_xen_opts=
wait_and_wakeup=
timeout=120
domU_type="pvh"
domU_vif="'bridge=xenbr0',"
domU_extra_config=
retrieve_xml=

case "${test_variant}" in
    ### test: smoke test & smoke test PVH & smoke test HVM & smoke test PVSHIM
    ""|"dom0pvh"|"dom0pvh-hvm"|"pvshim")
        passed="ping test passed"
        domU_check="
ifconfig eth0 192.168.0.2
until ping -c 10 192.168.0.1; do
    sleep 1
done
echo \"${passed}\"
"
        dom0_check="
set +x
until grep -q \"${passed}\" /var/log/xen/console/guest-domU.log; do
    sleep 1
done
set -x
echo \"${passed}\"
"
        if [ "${test_variant}" = "dom0pvh" ] || [ "${test_variant}" = "dom0pvh-hvm" ]; then
            extra_xen_opts="dom0=pvh"
        fi

        if [ "${test_variant}" = "dom0pvh-hvm" ]; then
            domU_type="hvm"
        elif [ "${test_variant}" = "pvshim" ]; then
            domU_type="pvh"
            domU_extra_config='pvshim = 1'
        fi
        ;;

    ### test: S3
    "s3")
        passed="suspend test passed"
        wait_and_wakeup="started, suspending"
        domU_check="
ifconfig eth0 192.168.0.2
echo domU started
"
        dom0_check="
until grep 'domU started' /var/log/xen/console/guest-domU.log; do
    sleep 1
done
echo \"${wait_and_wakeup}\"
# let the above message flow to console, then suspend
sync /dev/stdout
sleep 5
set -x
echo deep > /sys/power/mem_sleep
echo mem > /sys/power/state
xl list
xl dmesg | grep 'Finishing wakeup from ACPI S3 state' || exit 1
# check if domU is still alive
ping -c 10 192.168.0.2 || exit 1
echo \"${passed}\"
"
        ;;

    ### test: pci-pv, pci-hvm
    "pci-pv"|"pci-hvm")

        if [ -z "$PCIDEV" ]; then
            echo "Please set 'PCIDEV' variable with BDF of test network adapter" >&2
            echo "Optionally set also 'PCIDEV_INTR' to 'MSI' or 'MSI-X'" >&2
            exit 1
        fi

        passed="pci test passed"

        domU_type="${test_variant#pci-}"
        domU_vif=""

        domU_extra_config='
extra = "earlyprintk=xen"
pci = [ "'$PCIDEV',seize=1" ]
on_reboot = "destroy"
'

        domU_check="
set -x -e
interface=eth0
ip link set \"\$interface\" up
timeout 30s udhcpc -i \"\$interface\"
pingip=\$(ip -o -4 r show default|cut -f 3 -d ' ')
ping -c 10 \"\$pingip\"
echo domU started
pcidevice=\$(basename \$(readlink /sys/class/net/\$interface/device))
lspci -vs \$pcidevice
"
        if [ -n "$PCIDEV_INTR" ]; then
            domU_check="$domU_check
lspci -vs \$pcidevice | fgrep '$PCIDEV_INTR: Enable+'
"
        fi
        domU_check="$domU_check
echo \"${passed}\"
"

        dom0_check="
tail -F /var/log/xen/qemu-dm-domU.log &
until grep -q \"^domU Welcome to Alpine Linux\" /var/log/xen/console/guest-domU.log; do
    sleep 1
done
"
        ;;

    ### tests: tools-tests-pv, tools-tests-pvh
    "tools-tests-pv"|"tools-tests-pvh")
        retrieve_xml=1
        passed="test passed"
        domU_check=""
        dom0_check="
/tests/run-tools-tests /tests /tmp/tests-junit.xml && echo \"${passed}\"
nc -l -p 8080 < /tmp/tests-junit.xml >/dev/null &
"
        if [ "${test_variant}" = "tools-tests-pvh" ]; then
            extra_xen_opts="dom0=pvh"
        fi

        ;;

    *)
        echo "Unrecognised test_variant '${test_variant}'" >&2
        exit 1
        ;;
esac

domU_config="
type = '${domU_type}'
name = 'domU'
kernel = '/boot/vmlinuz'
ramdisk = '/boot/initrd-domU'
cmdline = 'root=/dev/ram0 console=hvc0'
memory = 512
vif = [ ${domU_vif} ]
disk = [ ]
${domU_extra_config}
"

if [ -n "$domU_check" ]; then
    # DomU
    mkdir -p rootfs
    cd rootfs
    # fakeroot is needed to preserve device nodes in rootless podman container
    fakeroot -s ../fakeroot-save tar xzf ../binaries/initrd.tar.gz
    mkdir proc
    mkdir run
    mkdir srv
    mkdir sys
    rm var/run
    echo "#!/bin/sh

${domU_check}
" > etc/local.d/xen.start
    chmod +x etc/local.d/xen.start
    echo "rc_verbose=yes" >> etc/rc.conf
    sed -i -e 's/^Welcome/domU \0/' etc/issue
    find . | fakeroot -i ../fakeroot-save cpio -H newc -o | gzip > ../binaries/domU-rootfs.cpio.gz
    cd ..
    rm -rf rootfs
fi

# DOM0 rootfs
mkdir -p rootfs
cd rootfs
fakeroot -s ../fakeroot-save tar xzf ../binaries/initrd.tar.gz
mkdir boot
mkdir proc
mkdir run
mkdir srv
mkdir sys
rm var/run
cp -ar ../binaries/dist/install/* .
cp -ar ../binaries/tests .
cp -a ../automation/scripts/run-tools-tests tests/

echo "#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/lib
bash /etc/init.d/xencommons start

brctl addbr xenbr0
brctl addif xenbr0 eth0
ifconfig eth0 up
ifconfig xenbr0 up
ifconfig xenbr0 192.168.0.1

" > etc/local.d/xen.start

if [ -n "$retrieve_xml" ]; then
    echo "timeout 30s udhcpc -i xenbr0" >> etc/local.d/xen.start
fi

if [ -n "$domU_check" ]; then
    echo "
# get domU console content into test log
tail -F /var/log/xen/console/guest-domU.log 2>/dev/null | sed -e \"s/^/(domU) /\" &
xl create /etc/xen/domU.cfg
${dom0_check}
" >> etc/local.d/xen.start
else
    echo "${dom0_check}" >> etc/local.d/xen.start
fi

chmod +x etc/local.d/xen.start
echo "$domU_config" > etc/xen/domU.cfg

echo "rc_verbose=yes" >> etc/rc.conf
echo "XENCONSOLED_TRACE=all" >> etc/default/xencommons
echo "QEMU_XEN=/bin/false" >> etc/default/xencommons
mkdir -p var/log/xen/console
cp ../binaries/bzImage boot/vmlinuz
if [ -n "$domU_check" ]; then
    cp ../binaries/domU-rootfs.cpio.gz boot/initrd-domU
fi
find . | fakeroot -i ../fakeroot-save cpio -H newc -o | gzip > ../binaries/dom0-rootfs.cpio.gz
cd ..


TFTP=/scratch/gitlab-runner/tftp
CONTROLLER=control@thor.testnet

echo "
multiboot2 (http)/gitlab-ci/xen $CONSOLE_OPTS loglvl=all guest_loglvl=all dom0_mem=4G console_timestamps=boot $extra_xen_opts
module2 (http)/gitlab-ci/vmlinuz console=hvc0 root=/dev/ram0 earlyprintk=xen
module2 (http)/gitlab-ci/initrd-dom0
" > $TFTP/grub.cfg

echo "#!ipxe

kernel /gitlab-ci/xen $CONSOLE_OPTS loglvl=all guest_loglvl=all dom0_mem=4G console_timestamps=boot $extra_xen_opts || reboot
module /gitlab-ci/vmlinuz console=hvc0 root=/dev/ram0 earlyprintk=xen || reboot
module /gitlab-ci/initrd-dom0 || reboot
boot
" > $TFTP/boot.ipxe

cp -f binaries/xen $TFTP/xen
cp -f binaries/bzImage $TFTP/vmlinuz
cp -f binaries/dom0-rootfs.cpio.gz $TFTP/initrd-dom0

# start logging the serial; this gives interactive console, don't close its
# stdin to not close it; the 'cat' is important, plain redirection would hang
# until somebody opens the pipe; opening and closing the pipe is used to close
# the console
mkfifo /tmp/console-stdin
cat /tmp/console-stdin |\
ssh $CONTROLLER console | tee smoke.serial | sed 's/\r//' &

# start the system pointing at gitlab-ci predefined config
ssh $CONTROLLER gitlabci poweron
trap "ssh $CONTROLLER poweroff; : > /tmp/console-stdin" EXIT

if [ -n "$wait_and_wakeup" ]; then
    # wait for suspend or a timeout
    until grep "$wait_and_wakeup" smoke.serial || [ $timeout -le 0 ]; do
        sleep 1;
        : $((--timeout))
    done
    if [ $timeout -le 0 ]; then
        echo "ERROR: suspend timeout, aborting"
        exit 1
    fi
    # keep it suspended a bit, then wakeup
    sleep 30
    ssh $CONTROLLER wake
fi

set +x
until grep "^Welcome to Alpine Linux" smoke.serial || [ $timeout -le 0 ]; do
    sleep 1;
    : $((--timeout))
done
set -x

tail -n 100 smoke.serial

if [ $timeout -le 0 ]; then
    echo "ERROR: test timeout, aborting"
    exit 1
fi

if [ -n "$retrieve_xml" ]; then
    nc -w 10 "$SUT_ADDR" 8080 > tests-junit.xml </dev/null
fi

sleep 1

(grep -q "^Welcome to Alpine Linux" smoke.serial && grep -q "${passed}" smoke.serial) || exit 1
exit 0
