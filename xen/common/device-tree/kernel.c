/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootinfo.h>
#include <xen/device_tree.h>
#include <xen/fdt-kernel.h>
#include <xen/errno.h>
#include <xen/gunzip.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <xen/vmap.h>

#include <asm/page.h>
#include <asm/setup.h>

static uint32_t __init output_length(char *image, unsigned long image_len)
{
    uint32_t val;

    memcpy(&val, &image[image_len - 4], sizeof(val));

    return val;
}

int __init kernel_decompress(struct boot_module *mod, uint32_t offset)
{
    char *output, *input;
    char magic[2];
    int rc;
    unsigned int kernel_order_out;
    paddr_t output_size;
    struct page_info *pages;
    mfn_t mfn;
    int i;
    paddr_t addr = mod->start;
    paddr_t size = mod->size;

    if ( size < offset )
        return -EINVAL;

    /*
     * It might be that gzip header does not appear at the start address
     * (e.g. in case of compressed uImage) so take into account offset to
     * gzip header.
     */
    addr += offset;
    size -= offset;

    if ( size < 2 )
        return -EINVAL;

    copy_from_paddr(magic, addr, sizeof(magic));

    /* only gzip is supported */
    if ( !gzip_check(magic, size) )
        return -EINVAL;

    input = ioremap_cache(addr, size);
    if ( input == NULL )
        return -EFAULT;

    output_size = output_length(input, size);
    kernel_order_out = get_order_from_bytes(output_size);
    pages = alloc_domheap_pages(NULL, kernel_order_out, 0);
    if ( pages == NULL )
    {
        iounmap(input);
        return -ENOMEM;
    }
    mfn = page_to_mfn(pages);
    output = vmap_contig(mfn, 1 << kernel_order_out);

    rc = perform_gunzip(output, input, size);
    clean_dcache_va_range(output, output_size);
    iounmap(input);
    vunmap(output);

    if ( rc )
    {
        free_domheap_pages(pages, kernel_order_out);
        return rc;
    }

    mod->start = page_to_maddr(pages);
    mod->size = output_size;

    /*
     * Need to free pages after output_size here because they won't be
     * freed by discard_initial_modules
     */
    i = PFN_UP(output_size);
    for ( ; i < (1 << kernel_order_out); i++ )
        free_domheap_page(pages + i);

    /*
     * When using static heap feature, don't give boot_modules memory back to
     * the heap allocator
     */
    if ( using_static_heap )
        return 0;

    /*
     * When freeing the kernel, we need to pass the module start address and
     * size as they were before taking an offset to gzip header into account,
     * so that the entire region will be freed.
     */
    addr -= offset;
    size += offset;

    /*
     * Free the original kernel, update the pointers to the
     * decompressed kernel
     */
    fw_unreserved_regions(addr, addr + size, init_domheap_pages, 0);

    return 0;
}

/*
 * Say what a rejected boot module actually is.
 *
 * kernel_image_probe() returning -EINVAL surfaces as construct_dom0()'s
 * "Could not set up d0 guest OS (rc = -22)", which names neither the kernel
 * nor anything about it, and on a platform whose only log is the console ring
 * that is all there is to go on.  Every case below is a thing people really
 * hand Xen -- an arm64 kernel is routinely shipped zstd-compressed inside a
 * CONFIG_EFI_ZBOOT wrapper, and both that wrapper and a raw Image start with
 * "MZ", so the difference is not visible without knowing where to look.
 */
static void __init report_unusable_kernel(paddr_t addr, paddr_t size)
{
    unsigned char head[8] = { };
    unsigned char at56[4] = { };

    printk(XENLOG_ERR "Boot module at %#"PRIpaddr" is not a kernel image Xen can load.\n",
           addr);

    if ( size < sizeof(head) )
    {
        printk(XENLOG_ERR "  It is only %#"PRIpaddr" bytes long.\n", size);
        return;
    }

    copy_from_paddr(head, addr, sizeof(head));
    if ( size >= 56 + sizeof(at56) )
        copy_from_paddr(at56, addr + 56, sizeof(at56));

    if ( !memcmp(head, "\x28\xb5\x2f\xfd", 4) )
        printk(XENLOG_ERR "  It is a zstd stream.  Only gzip is decompressed here, so decompress it first.\n");
    else if ( !memcmp(head, "\375" "7zXZ", 6) )
        printk(XENLOG_ERR "  It is an xz stream.  Only gzip is decompressed here, so decompress it first.\n");
    else if ( !memcmp(head, "\x02\x21", 2) )
        printk(XENLOG_ERR "  It is an lz4 stream.  Only gzip is decompressed here, so decompress it first.\n");
    else if ( head[0] == 0x1f && (head[1] == 0x8b || head[1] == 0x9e) )
        printk(XENLOG_ERR "  It is gzip-compressed, so decompression itself failed.\n");
    else if ( !memcmp(head, "MZ", 2) && size >= 56 + sizeof(at56) &&
              !memcmp(at56, "\0\0\0\0", 4) )
        printk(XENLOG_ERR
               "  It is a PE image with no arm64 Image magic at offset 56, i.e. a\n"
               "  CONFIG_EFI_ZBOOT vmlinuz.efi.  Xen cannot unwrap one: use the raw\n"
               "  arch/arm64/boot/Image, or build with CONFIG_EFI_ZBOOT=n.\n");
    else
        printk(XENLOG_ERR
               "  First bytes %02x %02x %02x %02x %02x %02x %02x %02x, offset 56 %02x %02x %02x %02x\n"
               "  (a raw arm64 Image has \"ARM\\x64\" = 41 52 4d 64 at offset 56).\n",
               head[0], head[1], head[2], head[3],
               head[4], head[5], head[6], head[7],
               at56[0], at56[1], at56[2], at56[3]);
}

int __init kernel_probe(struct kernel_info *info,
                        const struct dt_device_node *domain)
{
    struct boot_module *mod = NULL;
    struct bootcmdline *cmd = NULL;
    struct dt_device_node *node;
    u64 kernel_addr, initrd_addr, dtb_addr, size;
    int rc;

    /*
     * We need to initialize start to 0. This field may be populated during
     * kernel_xxx_probe() if the image has a fixed entry point (for e.g.
     * uimage.ep).
     * We will use this to determine if the image has a fixed entry point or
     * the load address should be used as the start address.
     */
    info->entry = 0;

    /* domain is NULL only for the hardware domain */
    if ( domain == NULL )
    {
        ASSERT(is_hardware_domain(info->bd.d));

        mod = boot_module_find_by_kind(BOOTMOD_KERNEL);

        info->bd.kernel = mod;
        info->bd.initrd = boot_module_find_by_kind(BOOTMOD_RAMDISK);

        cmd = boot_cmdline_find_by_kind(BOOTMOD_KERNEL);
        if ( cmd )
            info->bd.cmdline = &cmd->cmdline[0];
    }
    else
    {
        const char *name = NULL;

        dt_for_each_child_node(domain, node)
        {
            if ( dt_device_is_compatible(node, "multiboot,kernel") )
            {
                u32 len;
                const __be32 *val;

                val = dt_get_property(node, "reg", &len);
                dt_get_range(&val, node, &kernel_addr, &size);
                mod = boot_module_find_by_addr_and_kind(
                        BOOTMOD_KERNEL, kernel_addr);
                info->bd.kernel = mod;
            }
            else if ( dt_device_is_compatible(node, "multiboot,ramdisk") )
            {
                u32 len;
                const __be32 *val;

                val = dt_get_property(node, "reg", &len);
                dt_get_range(&val, node, &initrd_addr, &size);
                info->bd.initrd = boot_module_find_by_addr_and_kind(
                        BOOTMOD_RAMDISK, initrd_addr);
            }
            else if ( dt_device_is_compatible(node, "multiboot,device-tree") )
            {
                uint32_t len;
                const __be32 *val;

                val = dt_get_property(node, "reg", &len);
                if ( val == NULL )
                    continue;
                dt_get_range(&val, node, &dtb_addr, &size);
                info->dtb = boot_module_find_by_addr_and_kind(
                        BOOTMOD_GUEST_DTB, dtb_addr);
            }
            else
                continue;
        }
        name = dt_node_name(domain);
        cmd = boot_cmdline_find_by_name(name);
        if ( cmd )
            info->bd.cmdline = &cmd->cmdline[0];
    }
    if ( !mod || !mod->size )
    {
        printk(XENLOG_ERR "Missing kernel boot module?\n");
        return -ENOENT;
    }

    printk("Loading %pd kernel from boot module @ %"PRIpaddr"\n",
           info->bd.d, info->bd.kernel->start);
    if ( info->bd.initrd )
        printk("Loading ramdisk from boot module @ %"PRIpaddr"\n",
               info->bd.initrd->start);

    /*
     * uImage isn't really used nowadays thereby leave kernel_uimage_probe()
     * call here just for compatability with Arm code.
     */
#ifdef CONFIG_ARM
    /*
     * uImage header always appears at the top of the image (even compressed),
     * so it needs to be probed first. Note that in case of compressed uImage,
     * kernel_decompress is called from kernel_uimage_probe making the function
     * self-containing (i.e. fall through only in case of a header not found).
     */
    rc = kernel_uimage_probe(info, mod);
    if ( rc != -ENOENT )
        return rc;
#endif

    /*
     * If it is a gzip'ed image, 32bit or 64bit, uncompress it.
     * At this point, gzip header appears (if at all) at the top of the image,
     * so pass 0 as an offset.
     */
    rc = kernel_decompress(mod, 0);
    if ( rc && rc != -EINVAL )
        return rc;

    rc = kernel_image_probe(info, mod->start, mod->size);
    if ( rc )
        report_unusable_kernel(mod->start, mod->size);

    return rc;
}

void __init kernel_load(struct kernel_info *info)
{
    ASSERT(info && info->load);

    info->load(info);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
