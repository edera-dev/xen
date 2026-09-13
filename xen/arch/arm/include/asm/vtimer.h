/*
 * xen/arch/arm/vtimer.h
 *
 * ARM Virtual Timer emulation support
 *
 * Ian Campbell <ian.campbell@citrix.com>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ARCH_ARM_VTIMER_H__
#define __ARCH_ARM_VTIMER_H__

extern int domain_vtimer_init(struct domain *d,
                              struct xen_arch_domainconfig *config);
extern int vcpu_vtimer_init(struct vcpu *v);
extern bool vtimer_emulate(struct cpu_user_regs *regs, union hsr hsr);
/*
 * Re-enable the virtual timer's PPI on this pCPU.  vtimer_interrupt() masks it
 * when an interrupt arrives with no guest to inject into, because on some
 * platforms nothing Xen can write to the timer will quiet the line; switching
 * a guest in is what makes it wanted again.
 */
void vtimer_ppi_unmask(void);

extern void virt_timer_save(struct vcpu *v);
extern void virt_timer_restore(struct vcpu *v);
extern void vcpu_timer_destroy(struct vcpu *v);
void vtimer_update_irqs(struct vcpu *v);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
