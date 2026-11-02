/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <xen/vpci.h>

#include <asm/io.h>

void vpci_msix_arch_register(struct vpci_msix *msix, struct domain *d) { }

static int arm_msix_read(struct vcpu *v, mmio_info_t *info,
                         register_t *data, void *priv)
{
    struct vpci *vpci = (struct vpci *)priv;
    unsigned int len = 1U << info->dabt.size;
    unsigned long addr = info->gpa;
    int rc;

    read_lock(&v->domain->pci_lock);
    rc = vpci_msix_read(v->domain, vpci->msix, addr, len, data);
    read_unlock(&v->domain->pci_lock);

    return rc;
}

static int arm_msix_write(struct vcpu *v, mmio_info_t *info,
                          register_t data, void *priv)
{
    struct vpci *vpci = (struct vpci *)priv;
    unsigned int len = 1U << info->dabt.size;
    unsigned long addr = info->gpa;
    int rc;

    read_lock(&v->domain->pci_lock);
    rc = vpci_msix_write(v->domain, vpci->msix, addr, len, data);
    read_unlock(&v->domain->pci_lock);

    return rc;
}

static const struct mmio_handler_ops vpci_msi_mmio_handler = {
    .read  = arm_msix_read,
    .write = arm_msix_write,
};

int vpci_make_msix_hole(const struct pci_dev *pdev)
{
    (void) vpci_msi_mmio_handler;
    return 0;
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

