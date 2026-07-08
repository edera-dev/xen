# 02 — Page size and MMU granule

Status: design / analysis. This document owns the single most invasive
architectural decision in the whole port: **what translation granule does Xen
use on Apple Silicon?**

## 1. The problem in one paragraph

Xen/arm is hard-wired to a **4 KiB** translation granule
(`xen/arch/arm/include/asm/page-bits.h:4` — `#define PAGE_SHIFT 12`). The
Asahi Linux kernel we intend to run as dom0 is built **16 KiB-only**
(`arch/arm64/configs/asahi.config`: `CONFIG_ARM64_16K_PAGES=y`,
`# CONFIG_ARM64_4K_PAGES is not set`). macOS itself runs 16 KiB. So we have a
granule mismatch between the hypervisor and its intended dom0, and we must
decide whether Xen adopts 16 KiB, keeps 4 KiB, or something in between.

The good news, established in section 4, is that a guest's **stage‑1** granule
and the hypervisor's **stage‑2 / EL2 stage‑1** granule are *architecturally
independent*. That gives us a low-risk primary path.

## 2. Why Asahi/macOS use 16 KiB (and why it does NOT force Xen to)

There are three commonly-cited reasons the Apple platform "wants" 16 KiB. We
checked each against the source:

1. **The DART IOMMU.** *Not a hard constraint.* The Asahi DART page-table code
   explicitly supports both granules:
   `drivers/iommu/io-pgtable-dart.c:423` —
   `if (!(cfg->pgsize_bitmap == SZ_4K || cfg->pgsize_bitmap == SZ_16K))`.
   Individual DART instances on M1 are configured for 16 KiB to match the
   kernel, but the hardware/driver is granule-selectable.

2. **RTKit coprocessor firmware.** Real. Many Apple devices (NVMe, SMC, GPU,
   display, SEP) are coprocessors reached via mailboxes + shared memory mapped
   through a DART (`drivers/soc/apple/rtkit.c`). Some firmware blobs assume
   16 KiB-aligned shared buffers. **But this only affects whoever *drives the
   DART and talks to the coprocessor* — i.e. dom0 — not Xen's own page tables.**

3. **Matching the dom0 kernel.** Real but tautological: Asahi is 16 KiB, so
   dom0 is 16 KiB. This constrains *dom0's stage‑1*, not Xen's stage‑2.

Conclusion: **nothing forces Xen's own granule to be 16 KiB** *provided the CPU
implements a 4 KiB stage‑2 (and 4 KiB EL2 stage‑1) translation regime.* That
provision is the one hardware fact we must confirm (section 3).

## 3. The decisive hardware question (must be tested on real HW)

> Do Apple M1/M2 cores implement the **4 KiB granule** for the **EL2 stage‑1**
> regime (`TCR_EL2.TG0`) and the **stage‑2** regime (`VTCR_EL2.TG0`)?

This is reported by `ID_AA64MMFR0_EL1`:
- `TGran4` (bits [31:28]) — 4 KiB stage‑1 support.
- `TGran4_2` (bits [43:40]) — 4 KiB stage‑2 support (0b0000 = "use TGran4",
  0b0001 = not supported, 0b0010 = supported).

Xen already decodes these fields (`xen/arch/arm/include/asm/cpufeature.h:248‑253`
`tgranule_16K/64K/4K` and `tgranule_4k_2/16k_2/64k_2`), it just never *acts* on
them (it assumes 4 KiB).

**ANSWER (confirmed from a real M1 register dump): 4 KiB is supported at BOTH
stage‑1 and stage‑2.** The M1 reports
`ID_AA64MMFR0_EL1 = 0x000010000f100001` (recorded in the LLVM `apple-m1`
target, Dec 2020), which decodes as:

| Field | M1 value | Meaning |
|---|---|---|
| `TGran4` (S1 4 KiB) | 0b0000 | **supported** |
| `TGran16` (S1 16 KiB) | 0b0001 | supported |
| `TGran64` (S1 64 KiB) | 0b1111 | *not* supported |
| `TGran4_2` (S2 4 KiB) | 0b0000 | **supported** (mirrors S1) |
| `TGran16_2` (S2 16 KiB) | 0b0000 | supported |

So the "Apple has no 4 KiB pages" folklore is **false at the CPU level** — it is
64 KiB that is missing. This means **Path A (4 KiB Xen) is architecturally
valid.** Independently, the Xen ARM maintainer (Stefano Stabellini) proposed
exactly this on xen-devel in 2024: *"keep running Xen using 4 KiB pages and run
guests … which use 16 KiB pages."* (M2: no public register dump was found;
M1==M2 for page-size support is a strong inference — still read the register on
the actual target board via the fail-fast check in §8.)

**Still add the runtime check (§8):** don't trust folklore or even this doc —
read `ID_AA64MMFR0_EL1` on the target and fail fast if the configured granule
is unsupported at stage‑2. This is a one-line guard, not a research project.

## 4. Path A (RECOMMENDED): keep Xen at 4 KiB, dom0 stays 16 KiB

### 4.1 Why this is sound
ARMv8 stage‑1 and stage‑2 translations are independent walks with independent
granule configuration:
- dom0 (Asahi) runs its **stage‑1** at 16 KiB (`TCR_EL1.TG0` chosen by Linux).
- Xen runs its **EL2 stage‑1** (its own mappings) and the **guest stage‑2**
  (`VTCR_EL2`) at 4 KiB.
- A guest 16 KiB stage‑1 page produces an IPA; Xen's 4 KiB stage‑2 maps that
  IPA→PA at 4 KiB granularity. The CPU walks both regimes with their own TG0.
  This is exactly how a 4 KiB host kernel can run a 64 KiB guest on stock ARM
  server parts today.

### 4.2 The two things Path A must get right

**(a) dom0 memory must be 16 KiB-aligned and contiguous enough.**
Xen/arm direct-maps dom0 (guest PA == host PA;
`xen/arch/arm/domain_build.c:297` `BUG_ON(!is_domain_direct_mapped(d))`,
`:2261` `flags |= CDF_directmap`). The buddy allocator hands out
power-of-two-aligned, physically-contiguous extents, and dom0 allocation
already prefers large orders. A 16 KiB page is order‑2 in 4 KiB pages, so any
extent of order ≥ 2 is naturally 16 KiB-aligned. Action: ensure the dom0 bank
allocator floors extents to order ≥ 2 (trivial; it already targets far larger
orders). No stage‑2 change needed — 4 KiB stage‑2 can describe a 16 KiB-aligned
region perfectly.

**(b) The DART boundary (see `05-iommu-dart.md`).**
dom0 programs its DARTs with 16 KiB entries mapping *IPAs*. Because dom0 is
identity-mapped (IPA == PA), those DART entries already point at the correct
physical addresses with no Xen translation. This is the crucial reason Path A
works without a Xen DART driver on day one. It breaks only for **domU**
passthrough (non-identity guests), which is out of scope for the initial
milestones.

### 4.3 Cost of Path A
Near-zero MMU surgery. Xen stays exactly as it is on the granule front. The
entire "hard" 16 KiB porting effort in section 5 is deferred/avoided. Risk
concentrates on the one hardware fact in section 3.

### 4.4 Residual downside
- Stage‑2 tables are ~4× larger / more TLB pressure than a 16 KiB stage‑2 would
  be. Acceptable for bring-up; revisit under Path C if it hurts.
- If any Apple coprocessor firmware requires the *CPU-visible* mapping (not just
  DART) to be 16 KiB-aligned, a 4 KiB stage‑2 is still fine because alignment,
  not granule, is what matters, and (a) guarantees alignment.

## 5. Path B (fallback): make Xen itself 16 KiB

Required only if section 3 shows no 4 KiB stage‑2. This is the "HARD but
bounded" path. The Xen tree already contains a granule-parametric scaffold, so
the work concentrates in a handful of files rather than being smeared across
every consumer.

### 5.1 What already scales automatically
`xen/arch/arm/include/asm/lpae.h:200‑229` documents and implements
granule-generic shift macros:
```
Granularity | PAGE_SHIFT | LPAE_SHIFT
4K          | 12         | 9
16K         | 14         | 11
64K         | 16         | 13
#define LPAE_SHIFT_GS(gs)      ((gs) - 3)
#define LEVEL_SHIFT_GS(gs, lvl) (LEVEL_ORDER_GS(gs, lvl) + (gs))
```
`XEN_PT_LEVEL_*`, `THIRD_SIZE`, `DEFINE_PAGE_TABLE`, and the Image-header page
flag (`head.S:31` `__HEAD_FLAG_PAGE_SIZE ((PAGE_SHIFT-10)/2)` → 2 for 16 KiB)
all derive from `PAGE_SHIFT`, so bumping `PAGE_SHIFT` to 14 auto-scales the
arithmetic.

### 5.2 What must be hand-ported (the real work)
1. **LPAE descriptor bitfields** — `lpae.h` unions `lpae_pt_t` (`:46‑47`),
   `lpae_p2m_t` (`:89‑90`), `lpae_walk_t` (`:120`): `base:36 ... sbz:4`. The
   36‑bit output-address field starting at bit 12 is the *4 KiB* layout. At
   16 KiB the OA field starts at bit 14 (34 bits) and OA[51:48] relocate into
   descriptor bits[15:12]. These unions need a 16 KiB variant.
2. **Stage‑2 VTCR** — `xen/arch/arm/mmu/p2m.c:1767` `val |= VTCR_TG0_4K;`
   becomes `VTCR_TG0_16K`, and the `pa_range_info[]` table (`p2m.c:1702‑1718`,
   keyed to "ARM DDI 0487H.a Table D5‑6", the 4 KiB table) needs the 16 KiB
   `t0sz`/`sl0`/`root_order` values and a different `VTCR_SL0` encoding.
3. **arm64 virtual layout** — `xen/arch/arm/include/asm/mmu/layout.h:56`
   `SLOT0_ENTRY_BITS 39` assumes a 4 KiB 9‑bit L0 index (512 GiB/entry).
   16 KiB uses 11‑bit indices and a differently-sized top level; recompute
   `DIRECTMAP_VIRT_START`, `FRAMETABLE_VIRT_START`, `IDENTITY_MAPPING_AREA_NR_L0`.
4. **Boot page tables** — `xen/arch/arm/arm64/mmu/head.S:141‑263` builds a
   fixed 4-level `zeroeth/first/second/third` trie with 4 KiB attribute
   constants (`head.S:11‑15`); rework for the 16 KiB level count/indices.
5. **p2m root** — `p2m.c:1777‑1778` derives `p2m_root_order`/`p2m_root_level`
   from the 4 KiB table; and `mmu/p2m.c:1066` notes "The radix-tree can only
   work on 4KB" — audit and fix that assumption.
6. **Frametable sizing / directmap** — validate the `struct page_info` array
   stride and directmap window math under 14‑bit `PAGE_SHIFT`.

### 5.3 Cost of Path B
Weeks of careful MMU work plus a long debugging tail (early boot with wrong
page tables = silent hangs). Only pay this if section 3 forces it, or later as
an optimisation (Path C).

## 6. Path C (later optimisation): 16 KiB Xen for parity

Once bring-up works under Path A, a 16 KiB Xen becomes attractive because:
- stage‑2 and dom0 stage‑1 share a granule → simpler, cheaper DART passthrough
  for domU (a future Xen DART driver could share 16 KiB page tables the way
  `smmu.c:1276` shares the P2M today);
- smaller stage‑2 tables, less TLB pressure.
Treat Path C as a milestone *after* a booting system, reusing the section 5.2
work but now de-risked by a working reference.

## 7. Decision summary

| | Xen granule | dom0 granule | MMU work | DART day‑1 | Gate |
|---|---|---|---|---|---|
| **A (primary)** | 4 KiB | 16 KiB | ~none | identity dom0 only | needs 4 KiB stage‑2 |
| B (fallback) | 16 KiB | 16 KiB | HARD (§5.2) | identity dom0 only | if no 4 KiB stage‑2 |
| C (later) | 16 KiB | 16 KiB | HARD (reuse B) | enables domU DART | post-bring-up |

**Recommendation:** confirm `ID_AA64MMFR0_EL1.TGran4_2` on hardware (§3); if
4 KiB stage‑2 exists, take **Path A** and spend the saved effort on the
interrupt-controller work (`03`/`04`), which is the true critical path.

## 8. Concrete first action
Add a boot-time print + assertion in Xen's cpufeature init
(`xen/arch/arm/cpufeature.c:138`, where `ID_AA64MMFR0_EL1` is already read) that
decodes `tgranule_4k` / `tgranule_4k_2` and refuses to continue with a clear
message if the configured `PAGE_SHIFT` granule is unsupported at stage‑2. This
turns the "decisive hardware question" into a one-line, fail-fast check instead
of a mysterious early hang.
