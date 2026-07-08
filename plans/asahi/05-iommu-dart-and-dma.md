# 05 — IOMMU (DART/SART), DMA, and coprocessors

Status: design. Covers how DMA-capable devices reach memory on Apple Silicon,
why the initial port can largely *avoid* writing a Xen IOMMU driver, and what a
real one would take later.

## 1. The landscape: DART, SART, and coprocessors

Apple Silicon has three relevant pieces, none of which is an ARM SMMU:

1. **DART** (Device Address Resolution Table) — a per-device translating
   IOMMU with its own multi-level page tables, indexed by stream-ID (SID).
   Driver: `drivers/iommu/apple-dart.c` (1646 lines) +
   `drivers/iommu/io-pgtable-dart.c`.
2. **SART** — a simpler *address-filter* (allow-list of physical ranges, no
   remapping) used by the ANS2 NVMe coprocessor. Driver:
   `drivers/soc/apple/sart.c`.
3. **RTKit coprocessors** — NVMe (ANS2), DCP (display), GPU, SMC, ISP, SEP,
   audio (AOP): Apple-firmware IOPs reached via mailboxes + shared memory that
   is DMA-mapped through *their* DART/SART. Drivers: `drivers/soc/apple/rtkit.c`,
   `mailbox.c`. These reference memory by **IOVA**, meaningful only through
   their DART/SART.

Xen today ships only `smmu.c`/`smmu-v3.c`/`ipmmu-vmsa.c`
(`xen/drivers/passthrough/arm/`) and its ARM IOMMU model **shares the P2M page
tables** with the CPU (`smmu.c:1276` "The IOMMU share the page-tables with the
P2M"). DART shares nothing with the P2M and has a different table format, so
none of Xen's SMMU code is reusable.

## 2. The key enabler: Xen/arm direct-maps dom0 (IPA == PA)

Xen/arm direct-maps dom0 (`domain_build.c:297`
`BUG_ON(!is_domain_direct_mapped(d))`, `:2261` `CDF_directmap`). Therefore for
dom0 **guest-physical == machine-physical**. This is the single fact that lets
us defer a Xen DART driver:

- dom0 runs its **native** `apple-dart`/`sart`/`rtkit` drivers.
- When dom0 programs a DART/SART with a "physical" address, that address is
  already the true machine address (identity), so the coprocessor/device
  DMAs to the correct RAM with **no Xen translation needed**.
- Xen's only job for dom0 DMA is to *assign* the DART/SART MMIO regions and
  their IRQs to dom0 and otherwise stay out of the way.

This is the same reason Xen/arm can run dom0 on a no-IOMMU board today
(`docs/misc/arm/passthrough-noiommu.txt`; `arch_iommu_hwdom_init` is a near
no-op, `passthrough/arm/iommu.c:136-144`). IOMMU is **not mandatory** for dom0.

## 3. Page-size interaction (ties to doc 02)

The DART page granule is read from hardware
(`apple-dart.c:1362-1364`, `dart->pgsize = 1 << FIELD_GET(PARAMS1_PAGE_SHIFT)`)
and is **16 KiB** on M1-class DARTs. The Linux DART driver *refuses to build a
translating domain* and falls back to **identity/bypass** when
`dart->pgsize > PAGE_SIZE` (`:705`, `:1157-1170`, `:1442`).

Implication for our design (confirming doc 02 Path A):
- dom0 is **16 KiB** (Asahi). So in dom0, `dart->pgsize (16K) == PAGE_SIZE
  (16K)` → dom0 builds *real translating* DART domains normally. Good.
- This is why dom0 must stay 16 KiB regardless of whether Xen is 4 KiB or
  16 KiB. It is **not** a constraint on Xen's own granule — Xen is not the one
  programming the DART in the direct-mapped-dom0 model.
- The `pgsize_bitmap` allocator accepts only 4K or 16K
  (`io-pgtable-dart.c:423`); a future Xen DART driver (§6) would use 16 KiB.

## 4. What Xen must still do for dom0 DMA (day one)

Even in the "let dom0 own the DARTs" model, Xen has responsibilities:

1. **Assign MMIO + IRQs.** Every DART/SART instance's register window and its
   fault IRQ must be mapped into dom0 and described in the dom0 DT (doc 07).
   Xen must **not** claim them for itself.
2. **Preserve firmware carveouts.** m1n1/iBoot reserve memory for coprocessor
   firmware (`reserved-memory` nodes, filled by the loader — doc 07 §DT). Xen
   must keep these regions out of the dom0 allocator and out of its own heap,
   and keep their identity mapping intact.
3. **Respect locked DARTs.** Some DARTs are **locked by firmware with a page
   table already installed** — notably the display/DCP DART set up by iBoot for
   the boot framebuffer (`apple-dart.c:392-427,728-762`,
   `DART_T8020_CONFIG_LOCK`/`DART_T8110_PROTECT_TTBR_TCR`). The Linux driver
   *adopts* the existing config rather than resetting it. Xen must not stomp
   these; just hand them to dom0, which will also adopt them.
4. **Accept the trust model.** A DART/SART programmed by dom0 (and the
   coprocessor firmware it commands) can DMA anywhere the DART maps. With dom0
   identity-mapped and *trusted*, that is acceptable (dom0 already has effective
   full-machine access on Xen/arm). But note the residual risk: a buggy/hostile
   **coprocessor** could DMA outside intended bounds. For the initial port dom0
   is trusted, so this is a documented limitation, not a blocker.

## 5. SART specifics (NVMe root disk)

The internal SSD (ANS2) uses **SART**, not a DART, for some DMA
(`sart.c:5-12` "simple address filter … allow list … no remapping";
`drivers/nvme/host/apple.c:254-270` `apple_nvme_sart_dma_setup` →
`apple_sart_add_allowed_region`). SART's model is "add this *physical* range to
the allow-list."

- **Direct-mapped dom0:** dom0 hands the coprocessor real physical addresses
  and adds real physical ranges to the SART allow-list. Works unchanged.
- **Non-identity guest (future):** breaks entirely — the driver would be
  handing out IPAs the SART treats as PAs. Any driver-domain NVMe would need
  Xen to intercept SART programming (§6). Out of scope initially.

Because ANS2's *interrupts* are ordinary AIC IRQs (mailbox), and its *DMA* is
SART-filtered physical, **dom0 can boot from the internal SSD in the earliest
phases** (see doc 04 §5) without any Xen IOMMU driver and without PCIe.

## 6. A real Xen DART driver (deferred — needed for domU passthrough)

Required only when we want **non-identity guests** to own real Apple devices
(driver domains, or passing a Thunderbolt/PCIe device to a domU). Scope:

- New backend under `xen/drivers/passthrough/arm/dart.c` registering
  `DT_DEVICE_START(..., DEVICE_IOMMU)` + `iommu_set_ops(...)` for compatibles
  `apple,t8103-dart`, `apple,t6000-dart`, `apple,t8110-dart`, and the
  `apple,t8103-usb4-dart`.
- Variants (`apple-dart.c:158-192,1471-1573`): `T8020` (OAS 36, fmt
  `APPLE_DART`, 16 SIDs), `T6000` (OAS 42, `APPLE_DART2`), `T8110` (256 SIDs,
  4-level, `ttbr_shift` 14). USB4 DART: 64 SIDs, TTBR @ 0x400, **no bypass**.
- Per-SID `TCR`/`TTBR` programming (`DART_TCR/TTBR`, `TCR_TRANSLATE_ENABLE`,
  `TCR_FOUR_LEVEL`), TLB invalidation (T8020 `STREAM_COMMAND`; T8110 `TLB_CMD`
  FLUSH_ALL/FLUSH_SID), and the fault decoders
  (`DART_T8020_ERROR`/`DART_T8110_ERROR`).
- Its own **16 KiB** page tables (DART1 PADDR mask `GENMASK(35,12)`; DART2 packs
  PA>>4 into `GENMASK(37,10)`; per-PTE sub-page start/end
  `GENMASK(63,52)`/`[51:40]`). Cannot reuse the shared-P2M SMMU model.
- Locked-DART adoption and bypass-capability probing
  (`DART_PARAMS2_BYPASS_SUPPORT`).
- This is a substantial standalone driver (closer in shape to Xen's x86 IOMMU
  drivers than to `smmu.c`). Pairs naturally with a 16 KiB Xen (doc 02 Path C)
  so DART tables and stage-2 share a granule.

## 7. `dma_bitsize` / addressing

Xen's platform layer exposes `arch_get_dma_bitsize()`
(`platform.c:149-152`, default 32). Apple DARTs have OAS 36–42 and RAM sits at
a high base (`memory@800000000`). Set the Apple platform's `dma_bitsize`
appropriately (doc 06) so Xen's allocator hands out addresses the devices /
DARTs can reach, and so dom0's 1:1 regions land where DART OAS can address.

## 8. Effort and risk

| Task | Phase | Difficulty |
|---|---|---|
| Assign DART/SART MMIO+IRQ to dom0; preserve carveouts & locked DARTs | 1–4 | LOW (DT + memory reservation) |
| dom0 native DART/SART/RTKit passthrough (identity) | 4 | LOW–MODERATE (mostly "don't interfere") |
| Xen DART driver for domU passthrough | later | HARD (new 16 KiB IOMMU backend) |
| Xen SART mediation for driver-domain NVMe | later | MODERATE-HARD |

**Bottom line:** the direct-mapped-dom0 property turns the IOMMU from a
day-one blocker into a *deferred feature*. The initial port assigns DARTs/SARTs
to a trusted, identity-mapped dom0 and writes **no** Xen IOMMU code. Isolation
of untrusted device users comes later with a real DART driver (best paired with
16 KiB Xen).
