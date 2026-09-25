// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ExpansionPak

#include "emitter.h"
#include "backend/c_cfg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* W-c O3 full form: MODERNGEKKO_INLINE_XLAT_FULL=1 (read at regen time)
 * lowers every guest load/store to GXRuntime's direct MEM1 accessors
 * (mem_*_direct): one constant-bound probe + native BE access on the hot
 * path, an OUT-OF-LINE slow tail for EXRAM/MMIO instead of the fat inline
 * probe chain, plain host-endian accesses for the BRX classes, and (with
 * -mmovbe on the module build) single-instruction byteswaps. Off by
 * default; OFF emits byte-identical legacy text. Selection is
 * codegen-time-only by design -- a runtime dual variant would add a branch
 * to both arms and double code size (see evidence/phase3-throughput-o3full.md). */
static int g_direct_mem_lowering = -1;

static int direct_mem_lowering(void) {
    if (g_direct_mem_lowering < 0) {
        const char* configured = getenv("MODERNGEKKO_INLINE_XLAT_FULL");
        g_direct_mem_lowering = (configured && strcmp(configured, "1") == 0) ? 1 : 0;
        if (g_direct_mem_lowering)
            printf("  emitter: direct memory-access lowering enabled\n");
    }
    return g_direct_mem_lowering;
}

/* Access-expression selector: picks the direct accessor text when the gate
 * is armed, else the legacy mem_* call text. Both forms take (ctx, ea).
 * (Name is historical: it selects whole access expressions, incl. stores.) */
static const char* mem_rd_expr(const char* legacy, const char* direct) {
    return direct_mem_lowering() ? direct : legacy;
}

#define RD32E  mem_rd_expr("mem_read32(ctx, ea)", "mem_read32_direct(ctx, ea)")
#define RD16E  mem_rd_expr("mem_read16(ctx, ea)", "mem_read16_direct(ctx, ea)")
#define RD8E   mem_rd_expr("mem_read8(ctx, ea)", "mem_read8_direct(ctx, ea)")
#define RD16SE mem_rd_expr("(u32)(s32)(s16)mem_read16(ctx, ea)", "(u32)(s32)(s16)mem_read16_direct(ctx, ea)")
#define WR32   mem_rd_expr("mem_write32", "mem_write32_direct")
#define WR16   mem_rd_expr("mem_write16", "mem_write16_direct")
#define WR8    mem_rd_expr("mem_write8", "mem_write8_direct")

/* ---- Guest-address translation (LRELOC P1) -------------------------------
 * Folder-mode batches can be linked at a SECOND-BANK base (EXRAM, >=0x9)
 * while every relocation is still applied against the RETAIL layout: patch
 * words come out byte-identical to the retail run, so intra-batch CFG math,
 * local-target decisions and folded constants need no encoder changes.
 * What must move is the CHUNK CODE'S ADDRESS IDENTITY: every emitted constant
 * or identifier that names a chunk entry/label in this module bank goes out
 * translated (+delta when inside the batch span), while DOL-range targets
 * (import module 0) stay retail so they keep matching the pinned DOL
 * dispatch tables and GXRuntime MEM1 accessors. Fallback calls carry a
 * TRANSLATED cia (LRELOC P10): the interpreter-side hook re-maps it through
 * TranslateRelAddress to the runtime R image before SingleStepInner, so the
 * fallback cannot execute stale retail bytes. Disassembly comments stay raw,
 * as do diagnostics that describe genuinely retail state. */
static int g_xlate_on = 0;
static u32 g_xlate_lo, g_xlate_hi, g_xlate_delta;
static u32 g_xlate_lit_count = 0;

void emit_set_guest_translation(u32 lo, u32 hi, u32 delta) {
    g_xlate_lo = lo;
    g_xlate_hi = hi;
    g_xlate_delta = delta;
    g_xlate_on = delta != 0u;
    if (g_xlate_on)
        printf("  emitter: guest translation ON "
               "[0x%08X..0x%08X] += 0x%08X\n", lo, hi, delta);
}

u32 emit_guest_addr(u32 addr) {
    if (!g_xlate_on || addr < g_xlate_lo || addr > g_xlate_hi)
        return addr;
    return addr + g_xlate_delta;
}

/* LRELOC P8: translate a composed 32-bit DATA literal (a non-reloc constant,
 * e.g. a self-pointer materialized by a lis/addi or ori pair in guest code).
 * Identity when translation is off or the composed value lies outside the
 * batch span. Counts every translated literal for auditability. */
u32 emit_guest_literal(u32 addr) {
    u32 t = emit_guest_addr(addr);
    if (t != addr)
        g_xlate_lit_count++;
    return t;
}

u32 emit_guest_literal_count(void) {
    return g_xlate_lit_count;
}


static u32 cr_field_shift(u8 crf) {
    return 4u * (7u - (u32)crf);
}

static u32 ppc_mask32(u8 mb, u8 me) {
    u32 mask = 0;
    u8 bit = mb;

    for (;;) {
        mask |= 0x80000000u >> bit;
        if (bit == me)
            break;
        bit = (u8)((bit + 1) & 31);
    }

    return mask;
}

static void emit_set_cr0_from_gpr(FILE* out, u8 reg) {
    fprintf(out, "        u32 cr_bits = 0;\n");
    fprintf(out, "        s32 cr_value = (s32)ctx->gpr[%u];\n", reg);
    fprintf(out, "        if (cr_value < 0)  cr_bits |= 0x8u;\n");
    fprintf(out, "        if (cr_value > 0)  cr_bits |= 0x4u;\n");
    fprintf(out, "        if (cr_value == 0) cr_bits |= 0x2u;\n");
    fprintf(out, "        cr_bits |= (ctx->xer >> 31) & 1u;\n");
    fprintf(out, "        ctx->cr = (ctx->cr & 0x0FFFFFFFu) | (cr_bits << 28);\n");
}

static void emit_set_cr1_from_fpscr(FILE* out) {
    fprintf(out, "        ctx->cr = (ctx->cr & 0xF0FFFFFFu) | ((ctx->fpscr >> 4) & 0x0F000000u);\n");
}

static void emit_compare_s32(FILE* out, u8 crf, const char* lhs, const char* rhs) {
    u32 shift = cr_field_shift(crf);

    fprintf(out, "    {\n");
    fprintf(out, "        s32 val_a = (s32)(%s);\n", lhs);
    fprintf(out, "        s32 val_b = (s32)(%s);\n", rhs);
    fprintf(out, "        u32 cr_bits = 0;\n");
    fprintf(out, "        if (val_a < val_b)  cr_bits |= 0x8u;\n");
    fprintf(out, "        if (val_a > val_b)  cr_bits |= 0x4u;\n");
    fprintf(out, "        if (val_a == val_b) cr_bits |= 0x2u;\n");
    fprintf(out, "        cr_bits |= (ctx->xer >> 31) & 1u;\n");
    fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (cr_bits << %u);\n",
            shift, shift);
    fprintf(out, "    }\n");
}

static void emit_compare_u32(FILE* out, u8 crf, const char* lhs, const char* rhs) {
    u32 shift = cr_field_shift(crf);

    fprintf(out, "    {\n");
    fprintf(out, "        u32 val_a = (u32)(%s);\n", lhs);
    fprintf(out, "        u32 val_b = (u32)(%s);\n", rhs);
    fprintf(out, "        u32 cr_bits = 0;\n");
    fprintf(out, "        if (val_a < val_b)  cr_bits |= 0x8u;\n");
    fprintf(out, "        if (val_a > val_b)  cr_bits |= 0x4u;\n");
    fprintf(out, "        if (val_a == val_b) cr_bits |= 0x2u;\n");
    fprintf(out, "        cr_bits |= (ctx->xer >> 31) & 1u;\n");
    fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (cr_bits << %u);\n",
            shift, shift);
    fprintf(out, "    }\n");
}

static void emit_ps_merge(FILE* out, const PPCInst* inst,
                          bool use_a_ps1, bool use_b_ps1) {
    const char* a_bank = use_a_ps1 ? "ps1" : "fpr";
    const char* b_bank = use_b_ps1 ? "ps1" : "fpr";

    fprintf(out, "    {\n");
    fprintf(out, "        f64 ps0 = ctx->%s[%u];\n",
            a_bank, inst->rA);
    fprintf(out, "        f64 ps1 = ctx->%s[%u];\n",
            b_bank, inst->rB);
    fprintf(out, "        ctx->fpr[%u] = ps0;\n", inst->rD);
    fprintf(out, "        ctx->ps1[%u] = ps1;\n", inst->rD);
    fprintf(out, "    }\n");
}

static void emit_fcompare(FILE* out, const PPCInst* inst) {
    fprintf(out, "    ppc_fcmp(ctx, %u, ctx->fpr[%u], ctx->fpr[%u], %s);\n",
            inst->crfD, inst->rA, inst->rB,
            inst->op == PPC_OP_FCMPO ? "true" : "false");
}

static void emit_dform_ea(FILE* out, u8 ra, s16 simm, bool update) {
    if (ra == 0 && !update) {
        fprintf(out, "(u32)(s32)(%d)", (int)simm);
    } else {
        fprintf(out, "ctx->gpr[%u] + (u32)(s32)(%d)", ra, (int)simm);
    }
}

static void emit_xform_ea(FILE* out, u8 ra, u8 rb, bool update) {
    if (ra == 0 && !update) {
        fprintf(out, "ctx->gpr[%u]", rb);
    } else {
        fprintf(out, "ctx->gpr[%u] + ctx->gpr[%u]", ra, rb);
    }
}

static void emit_load(FILE* out, const PPCInst* inst, const char* read_expr,
                      bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_dform_ea(out, inst->rA, inst->simm, update);
    fprintf(out, ";\n");
    fprintf(out, "        ctx->gpr[%u] = %s;\n", inst->rD, read_expr);
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_loadx(FILE* out, const PPCInst* inst, const char* read_expr,
                       bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_xform_ea(out, inst->rA, inst->rB, update);
    fprintf(out, ";\n");
    fprintf(out, "        ctx->gpr[%u] = %s;\n", inst->rD, read_expr);
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_store(FILE* out, const PPCInst* inst, const char* write_func,
                       const char* cast_type, bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_dform_ea(out, inst->rA, inst->simm, update);
    fprintf(out, ";\n");
    fprintf(out, "        %s(ctx, ea, (%s)ctx->gpr[%u]);\n",
            write_func, cast_type, inst->rS);
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_storex(FILE* out, const PPCInst* inst, const char* write_func,
                        const char* cast_type, bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_xform_ea(out, inst->rA, inst->rB, update);
    fprintf(out, ";\n");
    fprintf(out, "        %s(ctx, ea, (%s)ctx->gpr[%u]);\n",
            write_func, cast_type, inst->rS);
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_fload(FILE* out, const PPCInst* inst, bool single,
                       bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_dform_ea(out, inst->rA, inst->simm, update);
    fprintf(out, ";\n");
    if (single) {
        fprintf(out, "        f64 value = dolrecomp_f32_from_bits(%s);\n",
                mem_rd_expr("mem_read32(ctx, ea)", "mem_read32_direct(ctx, ea)"));
        fprintf(out, "        ctx->fpr[%u] = value;\n", inst->rD);
        fprintf(out, "        ctx->ps1[%u] = value;\n", inst->rD);
    } else {
        fprintf(out, "        ctx->fpr[%u] = dolrecomp_f64_from_bits(%s);\n", inst->rD,
                mem_rd_expr("mem_read64(ctx, ea)", "mem_read64_direct(ctx, ea)"));
    }
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_floadx(FILE* out, const PPCInst* inst, bool single,
                        bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_xform_ea(out, inst->rA, inst->rB, update);
    fprintf(out, ";\n");
    if (single) {
        fprintf(out, "        f64 value = dolrecomp_f32_from_bits(%s);\n",
                mem_rd_expr("mem_read32(ctx, ea)", "mem_read32_direct(ctx, ea)"));
        fprintf(out, "        ctx->fpr[%u] = value;\n", inst->rD);
        fprintf(out, "        ctx->ps1[%u] = value;\n", inst->rD);
    } else {
        fprintf(out, "        ctx->fpr[%u] = dolrecomp_f64_from_bits(%s);\n", inst->rD,
                mem_rd_expr("mem_read64(ctx, ea)", "mem_read64_direct(ctx, ea)"));
    }
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_fstore(FILE* out, const PPCInst* inst, bool single,
                        bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_dform_ea(out, inst->rA, inst->simm, update);
    fprintf(out, ";\n");
    if (single) {
        fprintf(out, "        %s(ctx, ea, dolrecomp_f32_to_bits(ctx->fpr[%u]));\n",
                mem_rd_expr("mem_write32", "mem_write32_direct"), inst->rS);
    } else {
        fprintf(out, "        %s(ctx, ea, dolrecomp_f64_to_bits(ctx->fpr[%u]));\n",
                mem_rd_expr("mem_write64", "mem_write64_direct"), inst->rS);
    }
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_fstorex(FILE* out, const PPCInst* inst, bool single,
                         bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_xform_ea(out, inst->rA, inst->rB, update);
    fprintf(out, ";\n");
    if (single) {
        fprintf(out, "        %s(ctx, ea, dolrecomp_f32_to_bits(ctx->fpr[%u]));\n",
                mem_rd_expr("mem_write32", "mem_write32_direct"), inst->rS);
    } else {
        fprintf(out, "        %s(ctx, ea, dolrecomp_f64_to_bits(ctx->fpr[%u]));\n",
                mem_rd_expr("mem_write64", "mem_write64_direct"), inst->rS);
    }
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_psq_load(FILE* out, const PPCInst* inst, bool indexed,
                          bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    if (indexed) {
        emit_xform_ea(out, inst->rA, inst->rB, update);
    } else {
        emit_dform_ea(out, inst->rA, inst->simm, update);
    }
    fprintf(out, ";\n");
    fprintf(out, "        ppc_psq_load_inline(ctx, %uu, ea, %s, %uu, %s, 0x%08Xu);\n",
            inst->rD, inst->w ? "true" : "false", inst->i,
            indexed ? "true" : "false", inst->address);
    fprintf(out, "        if (ctx->exception) return;\n");
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_psq_store(FILE* out, const PPCInst* inst, bool indexed,
                           bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    if (indexed) {
        emit_xform_ea(out, inst->rA, inst->rB, update);
    } else {
        emit_dform_ea(out, inst->rA, inst->simm, update);
    }
    fprintf(out, ";\n");
    fprintf(out, "        ppc_psq_store_inline(ctx, %uu, ea, %s, %uu, %s, 0x%08Xu);\n",
            inst->rS, inst->w ? "true" : "false", inst->i,
            indexed ? "true" : "false", inst->address);
    fprintf(out, "        if (ctx->exception) return;\n");
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_dcbz(FILE* out, const PPCInst* inst) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_xform_ea(out, inst->rA, inst->rB, false);
    fprintf(out, ";\n");
    fprintf(out, "        ea &= ~31u;\n");
    fprintf(out, "        for (u32 i = 0; i < 32; i += 4) %s(ctx, ea + i, 0);\n",
            mem_rd_expr("mem_write32", "mem_write32_direct"));
    fprintf(out, "    }\n");
}

static void emit_branch_condition(FILE* out, u8 bo, u8 bi) {
    bool ctr_ignored = (bo & 0x04) != 0;
    bool cond_ignored = (bo & 0x10) != 0;

    if (!ctr_ignored) {
        fprintf(out, "        ctx->ctr--;\n");
        fprintf(out, "        bool ctr_ok = (((ctx->ctr != 0) ? 1u : 0u) ^ %uu) != 0;\n",
                (bo >> 1) & 1u);
    } else {
        fprintf(out, "        bool ctr_ok = true;\n");
    }

    if (!cond_ignored) {
        u32 mask = 0x80000000u >> bi;
        fprintf(out, "        bool cr_ok = (((ctx->cr & 0x%08Xu) != 0) == %s);\n",
                mask, ((bo >> 3) & 1u) ? "true" : "false");
    } else {
        fprintf(out, "        bool cr_ok = true;\n");
    }
}

static bool branch_target_is_local(u32 func_start, u32 func_end, u32 target) {
    return target >= func_start && target < func_end && ((target - func_start) & 3u) == 0;
}

// Chunk entry addresses, sorted. Written once before the worker pool starts and
// read-only thereafter, so no locking. NULL means "no table": every cross-chunk
// branch takes the safe return-to-chassis path.
static const u32* g_chunk_starts = NULL;
static u32 g_chunk_count = 0;

void emit_set_chunk_table(const u32* starts, u32 count) {
    g_chunk_starts = count ? starts : NULL;
    g_chunk_count = count ? count : 0;
}

/* Host-call hook guest addresses (env DOLRECOMP_HOST_HOOKS), sorted ascending.
 * Same lifetime model as the chunk table: written once before the worker pool
 * starts and read-only thereafter, so no locking. NULL means "no hooks": no
 * inline dispatch sites are emitted and generated text is unchanged. */
static const u32* g_host_hooks = NULL;
static u32 g_host_hook_count = 0;

/* GCC runtime gpr save/restore stubs are contiguous run-in sequences:
 *   save: [save_lo, save_hi] -- stw r_i at (r11 + 4*i - 128), i from
 *          14 + (target - save_lo)/4 through r31; save_hi is the tail blr.
 *   rest: [rest_lo, rest_hi] -- lwz r_i likewise; rest_hi is the tail blr.
 * A `bl` to any of those is semantics-exact to inline: the stubs only touch
 * gpr[14..31] and memory, then blr back to lr. Each site otherwise costs a
 * full chassis dispatch round trip (~5422 sites in GZLE01). Enabled via
 * DOLRECOMP_GPR_STUBS=save_lo:save_hi,rest_lo:rest_hi (retail hex). */
static u32 g_gpr_save_lo = 0, g_gpr_save_hi = 0;
static u32 g_gpr_rest_lo = 0, g_gpr_rest_hi = 0;

void emit_set_gpr_stub_ranges(u32 save_lo, u32 save_hi,
                              u32 rest_lo, u32 rest_hi) {
    g_gpr_save_lo = save_lo;
    g_gpr_save_hi = save_hi;
    g_gpr_rest_lo = rest_lo;
    g_gpr_rest_hi = rest_hi;
}

void emit_set_host_hooks(const u32* addrs, u32 count) {
    g_host_hooks = count ? addrs : NULL;
    g_host_hook_count = count ? count : 0;
}

// Sorted-table membership test. The env list holds RETAIL guest addresses;
// callers probe both inst->address and its translated form so REL batches
// linked under --l-base-offset match either convention.
static bool host_hook_at(u32 addr) {
    if (!g_host_hooks || !g_host_hook_count)
        return false;
    u32 lo = 0, hi = g_host_hook_count;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2u;
        if (g_host_hooks[mid] < addr)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return lo < g_host_hook_count && g_host_hooks[lo] == addr;
}

// The chunk whose func_<start>() covers `addr`, or 0 if none does. Chunks tile
// the text sections but the first one does not start on the common stride, so
// this binary-searches rather than dividing.
static u32 chunk_start_for(u32 addr) {
    if (!g_chunk_starts || !g_chunk_count)
        return 0;
    u32 lo = 0, hi = g_chunk_count;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2u;
        if (g_chunk_starts[mid] <= addr)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return lo ? g_chunk_starts[lo - 1u] : 0;
}


// A cross-chunk `bl` whose target chunk is known: call it directly instead of
// returning to the chassis. The chassis round trip costs two rel-section scans,
// two IsHostCallAddress hash lookups, a ModManager dispatch and a downcount
// flush, none of which a same-module call needs.
//
// Resume inline only if the callee came back to the instruction after the call.
// Any other pc means it stopped early -- budget exhausted, an exception, a
// tail-call elsewhere -- and only the chassis knows what to do next.
//
// The prototype is declared at block scope so this needs no header plumbing;
// the definition lives in another translation unit and the linker resolves it.
/* Emit the gpr stub body inline for a `bl` into a configured stub range.
 * The caller has already written ctx->lr = continuation. The stub then runs
 * its stw/lwz run-in and returns via blr, so after the ops we simply fall
 * through to the continuation block (every instruction boundary is labelled,
 * so it is always in scope). Returns false when the target is not a stub. */
static bool emit_gpr_stub_inline(FILE* out, const PPCInst* inst) {
    const u32 t = inst->branch_target;
    u32 first;
    bool save;
    if (g_gpr_save_hi && t >= g_gpr_save_lo && t <= g_gpr_save_hi) {
        first = (t == g_gpr_save_hi) ? 32u : 14u + (t - g_gpr_save_lo) / 4u;
        save = true;
    } else if (g_gpr_rest_hi && t >= g_gpr_rest_lo && t <= g_gpr_rest_hi) {
        first = (t == g_gpr_rest_hi) ? 32u : 14u + (t - g_gpr_rest_lo) / 4u;
        save = false;
    } else {
        return false;
    }
    /* The bl itself was already charged by the block head; charge the stub
     * body now (one stw/lwz per op) plus its blr. */
    fprintf(out, "            ctx->downcount -= %u;\n", (32u - first) + 1u);
    for (u32 i = first; i < 32u; ++i) {
        if (save)
            fprintf(out,
                    "            mem_write32_direct(ctx, (u32)(ctx->gpr[11] + (%d)), ctx->gpr[%u]);\n",
                    (int)(i * 4u - 128u), i);
        else
            fprintf(out,
                    "            ctx->gpr[%u] = mem_read32_direct(ctx, (u32)(ctx->gpr[11] + (%d)));\n",
                    i, (int)(i * 4u - 128u));
    }
    return true;
}

static bool emit_cross_chunk_call(FILE* out, const PPCInst* inst,
                                  u32 func_start, u32 func_end) {
    u32 continuation = inst->address + 4u;
    u32 target_chunk = chunk_start_for(inst->branch_target);
    if (!target_chunk)
        return false;
    // Without a local continuation label there is nothing to resume into, so
    // the call would buy nothing over the plain return.
    if (!branch_target_is_local(func_start, func_end, continuation))
        return false;

    fprintf(out, "            ctx->pc = 0x%08Xu;\n",
            emit_guest_addr(inst->branch_target));
    /* Guarded direct call: the per-site epoch cache memoizes the chassis
     * native-ok verdict for this constant target. g_mg_dcache_gen is bumped
     * by the chassis at every verdict-mutating event (hooks, REL relinks,
     * SMC invalidation, forced fallback, savestate restore) and once per
     * batch on runners that predate the epoch channel, so a cached verdict
     * cannot go stale while the callee runs. The replacement dispatcher still
     * runs on every call -- it has side effects (observer cases) and claims
     * REL/hook targets. */
    fprintf(out, "            {\n");
    fprintf(out, "                static u32 s_okgen_%08X;\n",
            inst->address);
    /* replacement first -- same order as dolrecomp_call: hooked targets are
     * claimed before the native verdict is queried, and observer cases have
     * side effects that must run on every call. */
    fprintf(out, "                if (dolrecomp_dispatch_replacement(ctx, 0x%08Xu)) {\n",
            emit_guest_addr(inst->branch_target));
    fprintf(out, "                    if (ctx->pc == 0x%08Xu) goto label_%08X;\n",
            emit_guest_addr(continuation), emit_guest_addr(continuation));
    fprintf(out, "                    return;\n");
    fprintf(out, "                }\n");
    fprintf(out, "                if (s_okgen_%08X != g_mg_dcache_gen) {\n",
            inst->address);
    fprintf(out, "                    if (g_mg_native_ok && g_mg_native_ok(0x%08Xu, g_mg_native_ok_user))\n",
            emit_guest_addr(inst->branch_target));
    fprintf(out, "                        s_okgen_%08X = g_mg_dcache_gen;\n",
            inst->address);
    fprintf(out, "                    else\n");
    fprintf(out, "                        return;\n");
    fprintf(out, "                }\n");
    fprintf(out, "                if (dolrecomp_call_enter()) {\n");
    fprintf(out, "                    void func_%08X(CPUState* ctx);\n",
            emit_guest_addr(target_chunk));
    fprintf(out, "                    func_%08X(ctx);\n", emit_guest_addr(target_chunk));
    fprintf(out, "                    dolrecomp_call_leave();\n");
    fprintf(out, "                    if (ctx->pc == 0x%08Xu) {\n",
            emit_guest_addr(continuation));
    fprintf(out, "                        if (ctx->downcount <= -(s64)DOLRECOMP_C_LOOP_CYCLE_BUDGET) return;\n");
    fprintf(out, "                        goto label_%08X;\n",
            emit_guest_addr(continuation));
    fprintf(out, "                    }\n");
    fprintf(out, "                }\n");
    fprintf(out, "            }\n");
    fprintf(out, "            return;\n");
    return true;
}

/* Same guarded direct call for a NON-link cross-chunk branch (tail call /
 * jump): no continuation label is needed because control never resumes here
 * -- when the callee exits (budget, exception, dynamic branch, its own
 * blr leaving the caller's return pc), we return to the dispatcher with
 * ctx->pc already set, exactly like the plain `pc=T; return` path. */
static bool emit_cross_chunk_jump(FILE* out, const PPCInst* inst) {
    u32 target_chunk = chunk_start_for(inst->branch_target);
    if (!target_chunk)
        return false;

    fprintf(out, "            ctx->pc = 0x%08Xu;\n",
            emit_guest_addr(inst->branch_target));
    fprintf(out, "            {\n");
    fprintf(out, "                static u32 s_okgen_%08X;\n",
            inst->address);
    fprintf(out, "                if (dolrecomp_dispatch_replacement(ctx, 0x%08Xu)) return;\n",
            emit_guest_addr(inst->branch_target));
    fprintf(out, "                if (s_okgen_%08X != g_mg_dcache_gen) {\n",
            inst->address);
    fprintf(out, "                    if (g_mg_native_ok && g_mg_native_ok(0x%08Xu, g_mg_native_ok_user))\n",
            emit_guest_addr(inst->branch_target));
    fprintf(out, "                        s_okgen_%08X = g_mg_dcache_gen;\n",
            inst->address);
    fprintf(out, "                    else\n");
    fprintf(out, "                        return;\n");
    fprintf(out, "                }\n");
    fprintf(out, "                if (dolrecomp_call_enter()) {\n");
    /* Tail-jump chains never re-enter the glue loop, so enforce the batch
     * budget here: an already-exhausted charge returns to the dispatcher
     * instead of stacking another host frame. */
    fprintf(out, "                    if (ctx->downcount <= -(s64)DOLRECOMP_C_LOOP_CYCLE_BUDGET) {\n");
    fprintf(out, "                        dolrecomp_call_leave();\n");
    fprintf(out, "                        return;\n");
    fprintf(out, "                    }\n");
    fprintf(out, "                    void func_%08X(CPUState* ctx);\n",
            emit_guest_addr(target_chunk));
    fprintf(out, "                    func_%08X(ctx);\n", emit_guest_addr(target_chunk));
    fprintf(out, "                    dolrecomp_call_leave();\n");
    fprintf(out, "                }\n");
    fprintf(out, "                return;\n");
    fprintf(out, "            }\n");
    return true;
}

static void emit_direct_branch(FILE* out, const PPCInst* inst,
                               bool local_target, bool direct_backedge,
                               u32 func_start, u32 func_end) {
    bool local_backward = local_target && inst->branch_target <= inst->address;

    if (inst->lk) {
        fprintf(out, "            ctx->lr = 0x%08Xu;\n",
                emit_guest_addr(inst->address + 4));
        if (emit_gpr_stub_inline(out, inst))
            return;
        if (local_target) {
            if (local_backward) {
                fprintf(out, "            if (ctx->downcount <= -(s64)DOLRECOMP_C_LOOP_CYCLE_BUDGET) {\n");
                fprintf(out, "                ctx->pc = 0x%08Xu;\n",
                        emit_guest_addr(inst->branch_target));
                fprintf(out, "                return;\n");
                fprintf(out, "            }\n");
            }
            fprintf(out, "            goto label_%08X;\n",
                    emit_guest_addr(inst->branch_target));
        } else if (!emit_cross_chunk_call(out, inst, func_start, func_end)) {
            fprintf(out, "            ctx->pc = 0x%08Xu;\n",
                    emit_guest_addr(inst->branch_target));
            fprintf(out, "            return;\n");
        }
        return;
    }
    if (local_backward) {
        if (direct_backedge) {
            fprintf(out, "            if (ctx->downcount <= -(s64)DOLRECOMP_C_LOOP_CYCLE_BUDGET) {\n");
            fprintf(out, "                ctx->pc = 0x%08Xu;\n",
                    emit_guest_addr(inst->branch_target));
            fprintf(out, "                return;\n");
            fprintf(out, "            }\n");
            fprintf(out, "            goto label_%08X;\n",
                    emit_guest_addr(inst->branch_target));
        } else {
            fprintf(out, "            ctx->pc = 0x%08Xu;\n",
                    emit_guest_addr(inst->branch_target));
            fprintf(out, "            return;\n");
        }
    } else if (local_target) {
        fprintf(out, "            goto label_%08X;\n",
                emit_guest_addr(inst->branch_target));
    } else if (!emit_cross_chunk_jump(out, inst)) {
        fprintf(out, "            ctx->pc = 0x%08Xu;\n",
                emit_guest_addr(inst->branch_target));
        fprintf(out, "            return;\n");
    }
}

static void emit_dynamic_branch(FILE* out, const PPCInst* inst,
                                const char* target_expr,
                                bool route_local_returns,
                                u32 function_address) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 target = %s;\n", target_expr);
    emit_branch_condition(out, inst->bo, inst->bi);
    fprintf(out, "        if (ctr_ok && cr_ok) {\n");
    if (inst->lk) {
        fprintf(out, "            ctx->lr = 0x%08Xu;\n",
                emit_guest_addr(inst->address + 4));
    }
    fprintf(out, "            ctx->pc = target;\n");
    if (route_local_returns)
        fprintf(out, "            goto return_dispatch_%08X;\n",
                emit_guest_addr(function_address));
    else
        fprintf(out, "            return;\n");
    fprintf(out, "        }\n");
    fprintf(out, "    }\n");
}

static void emit_cr_logical(FILE* out, const PPCInst* inst, const char* expr) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 a = (ctx->cr >> (31u - %uu)) & 1u;\n", inst->rA);
    fprintf(out, "        u32 b = (ctx->cr >> (31u - %uu)) & 1u;\n", inst->rB);
    fprintf(out, "        u32 mask = 0x80000000u >> %u;\n", inst->rD);
    fprintf(out, "        u32 value = (%s) & 1u;\n", expr);
    fprintf(out, "        ctx->cr = (ctx->cr & ~mask) | (value ? mask : 0u);\n");
    fprintf(out, "    }\n");
}

static void emit_record_if_needed(FILE* out, const PPCInst* inst, u8 reg) {
    if (inst->rc) {
        emit_set_cr0_from_gpr(out, reg);
    }
}

static const char* emit_cpu_macro(DolRecompCPU cpu) {
    switch (cpu) {
    case DOLRECOMP_CPU_BROADWAY:
        return "BROADWAY";
    case DOLRECOMP_CPU_ESPRESSO:
        return "ESPRESSO";
    case DOLRECOMP_CPU_GEKKO:
    default:
        return "GEKKO";
    }
}

static const char* emit_cpu_label(DolRecompCPU cpu) {
    switch (cpu) {
    case DOLRECOMP_CPU_BROADWAY:
        return "broadway";
    case DOLRECOMP_CPU_ESPRESSO:
        return "espresso";
    case DOLRECOMP_CPU_GEKKO:
    default:
        return "gekko";
    }
}

void emit_header_for_cpu(FILE* out, DolRecompCPU cpu) {
    fprintf(out,
        "// DolRecomp output\n"
        "// cpu: %s\n"
        "\n"
        "#ifndef RECOMP_GENERATED_H\n"
        "#define RECOMP_GENERATED_H\n"
        "\n"
        "#define DOLRECOMP_CPU_%s 1\n"
        "#define DOLRECOMP_CPU_NAME \"%s\"\n"
        "\n"
        "#include <string.h>\n"
        "#include <math.h>\n"
        "#ifndef DOLRECOMP_CPU_HEADER\n"
        "#define DOLRECOMP_CPU_HEADER \"cpu/cpu.h\"\n"
        "#endif\n"
        "#include DOLRECOMP_CPU_HEADER\n"
        "\n"
        "#ifndef DOLRECOMP_C_LOOP_CYCLE_BUDGET\n"
        "#define DOLRECOMP_C_LOOP_CYCLE_BUDGET 256\n"
        "#endif\n"
        "\n"
        "/* Cross-chunk calls turn guest recursion into host recursion, and a\n"
        "   chunk frame is not small. Without a ceiling a deep guest call chain\n"
        "   overflows the host stack, which is a crash rather than a slow\n"
        "   emulator. Past the limit the call site falls back to returning to\n"
        "   the chassis, which is always correct -- ctx->pc already names the\n"
        "   target, so the chassis simply dispatches it as it did before.\n"
        "   The counter is plain static, not atomic: the chassis runs the module\n"
        "   on one CPU thread. */\n"
        "#ifndef DOLRECOMP_C_MAX_CALL_DEPTH\n"
        "#define DOLRECOMP_C_MAX_CALL_DEPTH 24\n"
        "#endif\n"
        "extern unsigned dolrecomp_call_depth;\n"
        "static inline int dolrecomp_call_enter(void) {\n"
        "    if (dolrecomp_call_depth >= (unsigned)DOLRECOMP_C_MAX_CALL_DEPTH)\n"
        "        return 0;\n"
        "    dolrecomp_call_depth++;\n"
        "    return 1;\n"
        "}\n"
        "static inline void dolrecomp_call_leave(void) {\n"
        "    if (dolrecomp_call_depth)\n"
        "        dolrecomp_call_depth--;\n"
        "}\n"
        "\n"
        "static inline u32 dolrecomp_rotl32(u32 value, u32 sh) {\n"
        "    sh &= 31u;\n"
        "    return sh ? ((value << sh) | (value >> (32u - sh))) : value;\n"
        "}\n"
        "\n"
        // Preserve the PPC bit-level single conversion, including denormals.
        "static inline f64 dolrecomp_f32_from_bits(u32 bits) {\n"
        "    u64 x = bits;\n"
        "    u64 exp = (x >> 23) & 0xFFu;\n"
        "    u64 frac = x & 0x007FFFFFu;\n"
        "    u64 result;\n"
        "    if (exp > 0 && exp < 255) {\n"
        "        u64 y = !(exp >> 7);\n"
        "        u64 z = (y << 61) | (y << 60) | (y << 59);\n"
        "        result = ((x & 0xC0000000u) << 32) | z |\n"
        "                 ((x & 0x3FFFFFFFu) << 29);\n"
        "    } else if (exp == 0 && frac != 0) {\n"
        "        exp = 1023 - 126;\n"
        "        do {\n"
        "            frac <<= 1;\n"
        "            exp -= 1;\n"
        "        } while ((frac & 0x00800000u) == 0);\n"
        "        result = ((x & 0x80000000u) << 32) | (exp << 52) |\n"
        "                 ((frac & 0x007FFFFFu) << 29);\n"
        "    } else {\n"
        "        u64 y = exp >> 7;\n"
        "        u64 z = (y << 61) | (y << 60) | (y << 59);\n"
        "        result = ((x & 0xC0000000u) << 32) | z |\n"
        "                 ((x & 0x3FFFFFFFu) << 29);\n"
        "    }\n"
        "    f64 value;\n"
        "    memcpy(&value, &result, sizeof(value));\n"
        "    return value;\n"
        "}\n"
        "\n"
        "static inline u32 dolrecomp_f32_to_bits(f64 value) {\n"
        "    u64 bits;\n"
        "    memcpy(&bits, &value, sizeof(bits));\n"
        "    u32 exp = (u32)((bits >> 52) & 0x7FFu);\n"
        "    if (exp > 896 || (bits & 0x7FFFFFFFFFFFFFFFull) == 0) {\n"
        "        return (u32)(((bits >> 32) & 0xC0000000u) |\n"
        "                     ((bits >> 29) & 0x3FFFFFFFu));\n"
        "    }\n"
        "    if (exp >= 874) {\n"
        "        u32 result =\n"
        "            (u32)(0x80000000u | ((bits & 0x000FFFFFFFFFFFFFull) >> 21));\n"
        "        result >>= 905 - exp;\n"
        "        result |= (u32)((bits >> 32) & 0x80000000u);\n"
        "        return result;\n"
        "    }\n"
        "    return (u32)(((bits >> 32) & 0xC0000000u) |\n"
        "                 ((bits >> 29) & 0x3FFFFFFFu));\n"
        "}\n"
        "\n"
        "static inline f64 dolrecomp_f64_from_bits(u64 bits) {\n"
        "    f64 value;\n"
        "    memcpy(&value, &bits, sizeof(value));\n"
        "    return value;\n"
        "}\n"
        "\n"
        "static inline u64 dolrecomp_f64_to_bits(f64 value) {\n"
        "    u64 bits;\n"
        "    memcpy(&bits, &value, sizeof(bits));\n"
        "    return bits;\n"
        "}\n"
        "\n"
        "static inline f64 dolrecomp_ps_from_bits(u32 bits) {\n"
        "    return dolrecomp_f32_from_bits(bits);\n"
        "}\n"
        "\n"
        "static inline u32 dolrecomp_ps_to_bits(f64 value) {\n"
        "    return dolrecomp_f32_to_bits(value);\n"
        "}\n"
        "\n"
        ,
        emit_cpu_label(cpu),
        emit_cpu_macro(cpu),
        emit_cpu_label(cpu));
}

void emit_header(FILE* out) {
    emit_header_for_cpu(out, DOLRECOMP_CPU_GEKKO);
}

void emit_footer(FILE* out) {
    fprintf(out, "\n#endif /* RECOMP_GENERATED_H */\n\n// end\n");
}

/* True when a `bl` will get its gpr save/restore stub body inlined by
 * emit_gpr_stub_inline (same range test); the listing comment says so. */
static bool gpr_stub_inlined(const PPCInst* inst) {
    if (!inst->lk || (inst->op != PPC_OP_B && inst->op != PPC_OP_BC))
        return false;
    const u32 t = inst->branch_target;
    return (g_gpr_save_hi && t >= g_gpr_save_lo && t <= g_gpr_save_hi) ||
           (g_gpr_rest_hi && t >= g_gpr_rest_lo && t <= g_gpr_rest_hi);
}

/* Fallback-op tail. ppc_fallback_instruction's hooks finish a normal op with
 * ctx->pc == address+4 and no exception, the exact state a dispatcher round
 * trip would hand back. Inside a func_ body every instruction has a label, so
 * resume the next one in-chunk instead of returning: dcbx streaming loops
 * then stay inside their back-edge budget instead of dispatching once per
 * op. downcount != 0 keeps it exact: slow-path hooks (dcache-on, user-mode
 * dcbi, generic instruction_fallback) round-trip through SyncIn, which zeroes
 * the module's charge accumulator, and must return as before. Loop helpers
 * and single-instruction emission have no per-instruction labels. */
static void emit_fallback_return(FILE* out, const PPCInst* inst,
                                 u32 func_end, bool per_inst_labels) {
    const u32 next = inst->address + 4u;
    if (per_inst_labels && next < func_end) {
        fprintf(out, "    /* fb-fallthrough: a normal hook completion leaves ctx->pc == 0x%08X\n",
                emit_guest_addr(next));
        fprintf(out, "       and raises no exception -- the exact state a dispatcher round trip\n");
        fprintf(out, "       would hand back, so resuming the next label in-chunk is equivalent.\n");
        fprintf(out, "       Exceptions, hook redirects, or a slow-path SyncIn (dc==0) still return. */\n");
        fprintf(out, "    if (ctx->pc == 0x%08Xu && !ctx->exception && ctx->downcount != 0)\n",
                emit_guest_addr(next));
        fprintf(out, "        goto label_%08X;\n", emit_guest_addr(next));
    }
    fprintf(out, "    return;\n");
}

static void emit_instruction_with_range(FILE* out, const PPCInst* inst,
                                        u32 func_start, u32 func_end,
                                        bool direct_backedge,
                                        bool route_local_returns,
                                        bool per_inst_labels) {
    char disasm[64];
    ppc_disasm(disasm, sizeof(disasm), inst);
    fprintf(out, "    // %08X: %s%s\n", inst->address, disasm,
            gpr_stub_inlined(inst) ? "  [inlined gpr-stub]" : "");

    if (inst->embedded_data) {
        fprintf(out, "    // embedded data\n\n");
        return;
    }

    /* Inline host-call hook (emit_set_host_hooks / DOLRECOMP_HOST_HOOKS).
     * Runs before the fp gate and the instruction body so a skipping hook
     * (pc = lr) bypasses both. The chassis contract
     * (StaticRecompCore_Run.cpp): ppc_host_call true means a replacement
     * patch ran -- the original instruction must not execute and the
     * chassis re-dispatches ctx->pc. A hooks-only entry point returns
     * false through ModManager::Dispatch, so the pc-moved test alone
     * carries the entry-hook skip; a hook that leaves pc == address falls
     * through to the native body. */
    {
        const u32 hook_addr = emit_guest_addr(inst->address);
        if (host_hook_at(inst->address) || host_hook_at(hook_addr)) {
            fprintf(out, "    ctx->pc = 0x%08Xu;\n", hook_addr);
            fprintf(out,
                    "    if (ppc_host_call(ctx, 0x%08Xu) || ctx->pc != 0x%08Xu) return;\n",
                    hook_addr, hook_addr);
        }
    }

    if (ppc_op_uses_fpu(inst->op))
        /* LRELOC P14: the fp-gate cia becomes srr0 on a lazy-FP
         * FP-unavailable exception; the OS handler RFIs back to it, so
         * it MUST be the linked (translated) address or the restored pc
         * lands in the stale retail window (phase3-lreloc p12/p13 halts).
         * Same class as the p10 fallback-cia fix. */
        fprintf(out, "    if (!ppc_fp_available_inline(ctx, 0x%08Xu)) return;\n", emit_guest_addr(inst->address));
    switch (inst->op) {
    case PPC_OP_MULLI:
        /* LRELOC P10 (b): modelled mulli (upstream vendor had it; fork's
         * 345-line emitter rework dropped the case, routing every mulli to
         * the interpreter fallback). Parity with Dolphin's interpreter:
         * gpr[rD] = (u32)((s64)(s32)gpr[rA] * (s64)(s32)simm). */
        fprintf(out, "    ctx->gpr[%u] = (u32)((s64)(s32)ctx->gpr[%u] * (s64)(s32)%d);\n",
                inst->rD, inst->rA, (int)inst->simm);
        break;

    case PPC_OP_SUBFIC:
        /* LRELOC P10 (b): restored upstream case (fork's emitter rework
         * dropped it, routing subfic to the interpreter fallback).
         * carry = (simm + ~rA + 1) computed in 64-bit; CA = bit 32. */
        fprintf(out, "    {\n");
        fprintf(out, "        u64 res = (u64)(u32)(s32)(%d) + (u64)(~ctx->gpr[%u]) + 1u;\n",
                (int)inst->simm, inst->rA);
        fprintf(out, "        ctx->gpr[%u] = (u32)res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(res >> 32) & 1u) << 29);\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDI:
        if (inst->rA == 0) {
            u32 lit = emit_guest_literal((u32)(s32)(s32)inst->simm);
            fprintf(out, "    ctx->gpr[%u] = (u32)(s32)(%d);\n",
                    inst->rD, (int)(s32)lit);
        } else {
            fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] + (u32)(s32)(%d);\n",
                    inst->rD, inst->rA, (int)inst->simm);
        }
        break;


    case PPC_OP_ADDIC:
    case PPC_OP_ADDIC_DOT:
        fprintf(out, "    {\n");
        fprintf(out, "        u64 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u64 b = (u32)(s32)(%d);\n", (int)inst->simm);
        fprintf(out, "        u64 res = a + b;\n");
        fprintf(out, "        ctx->gpr[%u] = (u32)res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(res >> 32) & 1u) << 29);\n");
        if (inst->op == PPC_OP_ADDIC_DOT) {
            emit_set_cr0_from_gpr(out, inst->rD);
        }
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDIS:
        if (inst->rA == 0) {
            /* LRELOC P8: rA==0 means the HI page of an address literal. Translate
             * the composed page address when in span; delta low 16 bits are 0
             * (0x10C00000), so HI += delta>>16 and the later LO stays exact.
             * General form: recompute the page of the translated base. */
            u32 page = (u32)(s32)inst->simm << 16;
            u32 tpage = emit_guest_literal(page) & 0xFFFF0000u;
            fprintf(out, "    ctx->gpr[%u] = ((u32)(s32)(%d) << 16);\n",
                    inst->rD, (int)(s32)(tpage >> 16));
        } else {
            fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] + ((u32)(s32)(%d) << 16);\n",
                    inst->rD, inst->rA, (int)inst->simm);
        }
        break;

    case PPC_OP_CMPI:
        {
            char rhs[32];
            snprintf(rhs, sizeof(rhs), "%d", (int)inst->simm);
            char lhs[32];
            snprintf(lhs, sizeof(lhs), "ctx->gpr[%u]", inst->rA);
            emit_compare_s32(out, inst->crfD, lhs, rhs);
        }
        break;

    case PPC_OP_CMPLI:
        {
            char rhs[32];
            snprintf(rhs, sizeof(rhs), "0x%04Xu", inst->uimm);
            char lhs[32];
            snprintf(lhs, sizeof(lhs), "ctx->gpr[%u]", inst->rA);
            emit_compare_u32(out, inst->crfD, lhs, rhs);
        }
        break;

    case PPC_OP_CMP:
        {
            char lhs[32], rhs[32];
            snprintf(lhs, sizeof(lhs), "ctx->gpr[%u]", inst->rA);
            snprintf(rhs, sizeof(rhs), "ctx->gpr[%u]", inst->rB);
            emit_compare_s32(out, inst->crfD, lhs, rhs);
        }
        break;

    case PPC_OP_CMPL:
        {
            char lhs[32], rhs[32];
            snprintf(lhs, sizeof(lhs), "ctx->gpr[%u]", inst->rA);
            snprintf(rhs, sizeof(rhs), "ctx->gpr[%u]", inst->rB);
            emit_compare_u32(out, inst->crfD, lhs, rhs);
        }
        break;

    case PPC_OP_ORI:
        if (inst->rS == 0 && inst->rA == 0 && inst->uimm == 0) {
            fprintf(out, "    // nop\n");
        } else {
            fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] | 0x%04Xu;\n",
                    inst->rA, inst->rS, inst->uimm);
        }
        break;

    case PPC_OP_ORIS:
        /* oris has no rS==0 literal-base form (unlike the D-form rA=0 case for
         * addi/addis): rS==0 reads gpr[0] for real. The old LRELOC P8 shortcut
         * emitted "rD = uimm<<16" here, silently dropping the OR operand and
         * corrupting every "oris rD, r0, imm" in the game (e.g. GXSetDispCopySrc
         * lost its 0x4A dims word -> 1x1 XFB copy -> green screen). Keep the
         * LRELOC literal-page translation for genuine relocation literals —
         * gpr[0]|tpage matches the intended tpage wherever r0==0, which such
         * sequences require anyway — but always preserve the OR. */
        {
            u32 page = (u32)inst->uimm << 16;
            u32 tpage = emit_guest_literal(page) & 0xFFFF0000u;
            fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] | (0x%04Xu << 16);\n",
                    inst->rA, inst->rS, tpage >> 16);
        }
        break;

    case PPC_OP_XORI:
        fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] ^ 0x%04Xu;\n",
                inst->rA, inst->rS, inst->uimm);
        break;

    case PPC_OP_XORIS:
        fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] ^ (0x%04Xu << 16);\n",
                inst->rA, inst->rS, inst->uimm);
        break;

    case PPC_OP_ANDI:
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->gpr[%u] = ctx->gpr[%u] & 0x%04Xu;\n",
                inst->rA, inst->rS, inst->uimm);
        emit_set_cr0_from_gpr(out, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ANDIS:
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->gpr[%u] = ctx->gpr[%u] & (0x%04Xu << 16);\n",
                inst->rA, inst->rS, inst->uimm);
        emit_set_cr0_from_gpr(out, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADD:
    case PPC_OP_ADDO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u32 res = a + b;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDC:
    case PPC_OP_ADDCO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u64 wide = (u64)a + (u64)b;\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDE:
    case PPC_OP_ADDEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 carry = (ctx->xer >> 29) & 1u;\n");
        fprintf(out, "        u32 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u64 wide = (u64)a + (u64)b + carry;\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDME:
    case PPC_OP_ADDMEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 input = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 carry = (ctx->xer >> 29) & 1u;\n");
        fprintf(out, "        u64 res = (u64)input + 0xFFFFFFFFull + carry;\n");
        fprintf(out, "        ctx->gpr[%u] = (u32)res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | ((res >> 32) ? 0x20000000u : 0u);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(input, 0xFFFFFFFFu, (u32)res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDZE:
    case PPC_OP_ADDZEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u64 wide = (u64)a + ((ctx->xer >> 29) & 1u);\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, 0u, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SUBF:
    case PPC_OP_SUBFO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ~ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u32 res = a + b + 1u;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SUBFC:
    case PPC_OP_SUBFCO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ~ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u64 wide = (u64)b + (u64)a + 1u;\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SUBFE:
    case PPC_OP_SUBFEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ~ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u32 carry = (ctx->xer >> 29) & 1u;\n");
        fprintf(out, "        u64 wide = (u64)a + (u64)b + carry;\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SUBFME:
    case PPC_OP_SUBFMEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 input = ~ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 carry = (ctx->xer >> 29) & 1u;\n");
        fprintf(out, "        u64 res = (u64)input + 0xFFFFFFFFull + carry;\n");
        fprintf(out, "        ctx->gpr[%u] = (u32)res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | ((res >> 32) ? 0x20000000u : 0u);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(input, 0xFFFFFFFFu, (u32)res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SUBFZE:
    case PPC_OP_SUBFZEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ~ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u64 wide = (u64)a + ((ctx->xer >> 29) & 1u);\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, 0u, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_NEG:
    case PPC_OP_NEGO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        ctx->gpr[%u] = (~a) + 1u;\n", inst->rD);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, a == 0x80000000u);\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_MULLW:
    case PPC_OP_MULLWO:
        fprintf(out, "    {\n");
        fprintf(out, "        s64 product = (s64)(s32)ctx->gpr[%u] * (s64)(s32)ctx->gpr[%u];\n",
                inst->rA, inst->rB);
        fprintf(out, "        ctx->gpr[%u] = (u32)product;\n", inst->rD);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, product < -0x80000000ll || product > 0x7fffffffll);\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_MULHW:
        fprintf(out, "    {\n");
        fprintf(out, "        s64 product = (s64)(s32)ctx->gpr[%u] * (s64)(s32)ctx->gpr[%u];\n",
                inst->rA, inst->rB);
        fprintf(out, "        ctx->gpr[%u] = (u32)(product >> 32);\n", inst->rD);
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_MULHWU:
        fprintf(out, "    {\n");
        fprintf(out, "        u64 product = (u64)ctx->gpr[%u] * (u64)ctx->gpr[%u];\n",
                inst->rA, inst->rB);
        fprintf(out, "        ctx->gpr[%u] = (u32)(product >> 32);\n", inst->rD);
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_DIVW:
    case PPC_OP_DIVWO:
        fprintf(out, "    {\n");
        fprintf(out, "        s32 dividend = (s32)ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        s32 divisor = (s32)ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        bool ov = divisor == 0 || ((u32)dividend == 0x80000000u && divisor == -1);\n");
        fprintf(out, "        ctx->gpr[%u] = ov ? ((dividend < 0) ? 0xFFFFFFFFu : 0u) : (u32)(dividend / divisor);\n",
                inst->rD);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ov);\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_DIVWU:
    case PPC_OP_DIVWUO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 divisor = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        ctx->gpr[%u] = divisor == 0 ? 0u : ctx->gpr[%u] / divisor;\n",
                inst->rD, inst->rA);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, divisor == 0);\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_AND:
    case PPC_OP_ANDC:
    case PPC_OP_OR:
    case PPC_OP_ORC:
    case PPC_OP_XOR:
    case PPC_OP_NAND:
    case PPC_OP_NOR:
    case PPC_OP_EQV: {
        const char* expr = NULL;
        switch (inst->op) {
        case PPC_OP_AND:  expr = "ctx->gpr[%u] & ctx->gpr[%u]"; break;
        case PPC_OP_ANDC: expr = "ctx->gpr[%u] & ~ctx->gpr[%u]"; break;
        case PPC_OP_OR:   expr = "ctx->gpr[%u] | ctx->gpr[%u]"; break;
        case PPC_OP_ORC:  expr = "ctx->gpr[%u] | ~ctx->gpr[%u]"; break;
        case PPC_OP_XOR:  expr = "ctx->gpr[%u] ^ ctx->gpr[%u]"; break;
        case PPC_OP_NAND: expr = "~(ctx->gpr[%u] & ctx->gpr[%u])"; break;
        case PPC_OP_NOR:  expr = "~(ctx->gpr[%u] | ctx->gpr[%u])"; break;
        default:          expr = "~(ctx->gpr[%u] ^ ctx->gpr[%u])"; break;
        }
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->gpr[%u] = ", inst->rA);
        fprintf(out, expr, inst->rS, inst->rB);
        fprintf(out, ";\n");
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_CNTLZW:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 v = ctx->gpr[%u];\n", inst->rS);
        fprintf(out, "        u32 n = 0;\n");
        fprintf(out, "        while (n < 32 && ((v & (0x80000000u >> n)) == 0)) n++;\n");
        fprintf(out, "        ctx->gpr[%u] = n;\n", inst->rA);
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_EXTSB:
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->gpr[%u] = (u32)(s32)(s8)ctx->gpr[%u];\n",
                inst->rA, inst->rS);
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_EXTSH:
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->gpr[%u] = (u32)(s32)(s16)ctx->gpr[%u];\n",
                inst->rA, inst->rS);
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SLW:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 sh = ctx->gpr[%u] & 0x3Fu;\n", inst->rB);
        fprintf(out, "        ctx->gpr[%u] = sh > 31 ? 0u : (ctx->gpr[%u] << sh);\n",
                inst->rA, inst->rS);
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SRW:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 sh = ctx->gpr[%u] & 0x3Fu;\n", inst->rB);
        fprintf(out, "        ctx->gpr[%u] = sh > 31 ? 0u : (ctx->gpr[%u] >> sh);\n",
                inst->rA, inst->rS);
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SRAW:
    case PPC_OP_SRAWI:
        fprintf(out, "    {\n");
        if (inst->op == PPC_OP_SRAWI) {
            fprintf(out, "        u32 sh = %uu;\n", inst->sh);
        } else {
            fprintf(out, "        u32 sh = ctx->gpr[%u] & 0x3Fu;\n", inst->rB);
        }
        fprintf(out, "        u32 value = ctx->gpr[%u];\n", inst->rS);
        fprintf(out, "        bool ca = false;\n");
        fprintf(out, "        if (sh == 0) {\n");
        fprintf(out, "            ctx->gpr[%u] = value;\n", inst->rA);
        fprintf(out, "        } else if (sh > 31) {\n");
        fprintf(out, "            ctx->gpr[%u] = (value & 0x80000000u) ? 0xFFFFFFFFu : 0u;\n", inst->rA);
        fprintf(out, "            ca = (value & 0x80000000u) != 0;\n");
        fprintf(out, "        } else {\n");
        fprintf(out, "            ctx->gpr[%u] = (u32)((s32)value >> sh);\n", inst->rA);
        fprintf(out, "            ca = (value & 0x80000000u) && ((value << (32u - sh)) != 0);\n");
        fprintf(out, "        }\n");
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (ca ? 0x20000000u : 0u);\n");
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_RLWINM:
        {
            u32 mask = ppc_mask32(inst->mb, inst->me);
            fprintf(out, "    {\n");
            fprintf(out, "        ctx->gpr[%u] = dolrecomp_rotl32(ctx->gpr[%u], %uu) & 0x%08Xu;\n",
                    inst->rA, inst->rS, inst->sh, mask);
            emit_record_if_needed(out, inst, inst->rA);
            fprintf(out, "    }\n");
        }
        break;

    case PPC_OP_RLWNM:
        {
            u32 mask = ppc_mask32(inst->mb, inst->me);
            fprintf(out, "    {\n");
            fprintf(out, "        ctx->gpr[%u] = dolrecomp_rotl32(ctx->gpr[%u], ctx->gpr[%u]) & 0x%08Xu;\n",
                    inst->rA, inst->rS, inst->rB, mask);
            emit_record_if_needed(out, inst, inst->rA);
            fprintf(out, "    }\n");
        }
        break;

    case PPC_OP_RLWIMI:
        {
            u32 mask = ppc_mask32(inst->mb, inst->me);
            fprintf(out, "    {\n");
            fprintf(out, "        u32 rot = dolrecomp_rotl32(ctx->gpr[%u], %uu);\n",
                    inst->rS, inst->sh);
            fprintf(out, "        ctx->gpr[%u] = (ctx->gpr[%u] & ~0x%08Xu) | (rot & 0x%08Xu);\n",
                    inst->rA, inst->rA, mask, mask);
            emit_record_if_needed(out, inst, inst->rA);
            fprintf(out, "    }\n");
        }
        break;

    case PPC_OP_FADDS:
        fprintf(out, "    ppc_fadds(ctx, %u, %u, %u);\n", inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FSUBS:
        fprintf(out, "    ppc_fsubs(ctx, %u, %u, %u);\n", inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FMULS:
        fprintf(out, "    ppc_fmuls(ctx, %u, %u, %u);\n", inst->rD, inst->rA, inst->rC);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FDIVS:
        fprintf(out, "    ppc_fdivs(ctx, %u, %u, %u);\n", inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FRES:
        fprintf(out, "    { f64 result; if (ppc_fres(ctx, ctx->fpr[%u], &result)) ctx->fpr[%u] = ctx->ps1[%u] = result; }\n",
                inst->rB, inst->rD, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FMADDS:
    case PPC_OP_FMSUBS:
    case PPC_OP_FNMADDS:
    case PPC_OP_FNMSUBS: {
        const bool sub = inst->op == PPC_OP_FMSUBS || inst->op == PPC_OP_FNMSUBS;
        const bool neg = inst->op == PPC_OP_FNMADDS || inst->op == PPC_OP_FNMSUBS;
        fprintf(out, "    {\n");
        fprintf(out, "        f64 result;\n");
        fprintf(out, "        if (ppc_fma(ctx, ctx->fpr[%u], ctx->fpr[%u], ctx->fpr[%u], true, %s, %s, &result))\n",
                inst->rA, inst->rC, inst->rB, sub ? "true" : "false", neg ? "true" : "false");
        fprintf(out, "            ctx->fpr[%u] = ctx->ps1[%u] = result;\n", inst->rD, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_FADD:
        fprintf(out, "    ppc_fadd(ctx, %u, %u, %u);\n", inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FSUB:
        fprintf(out, "    ppc_fsub(ctx, %u, %u, %u);\n", inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FMUL:
        fprintf(out, "    ppc_fmul(ctx, %u, %u, %u);\n", inst->rD, inst->rA, inst->rC);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FDIV:
        fprintf(out, "    ppc_fdiv(ctx, %u, %u, %u);\n", inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FRSQRTE:
        fprintf(out, "    { f64 result; if (ppc_frsqrte(ctx, ctx->fpr[%u], &result)) ctx->fpr[%u] = result; }\n",
                inst->rB, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FMADD:
    case PPC_OP_FMSUB:
    case PPC_OP_FNMADD:
    case PPC_OP_FNMSUB: {
        const bool sub = inst->op == PPC_OP_FMSUB || inst->op == PPC_OP_FNMSUB;
        const bool neg = inst->op == PPC_OP_FNMADD || inst->op == PPC_OP_FNMSUB;
        fprintf(out, "    {\n");
        fprintf(out, "        f64 result;\n");
        fprintf(out, "        if (ppc_fma(ctx, ctx->fpr[%u], ctx->fpr[%u], ctx->fpr[%u], false, %s, %s, &result))\n",
                inst->rA, inst->rC, inst->rB, sub ? "true" : "false", neg ? "true" : "false");
        fprintf(out, "            ctx->fpr[%u] = result;\n", inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_FCTIW:
    case PPC_OP_FCTIWZ:
        fprintf(out, "    { u64 result; if (ppc_fctiw(ctx, ctx->fpr[%u], %s, &result)) ctx->fpr[%u] = dolrecomp_f64_from_bits(result); }\n",
                inst->rB, inst->op == PPC_OP_FCTIWZ ? "true" : "false", inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FMR:
        fprintf(out, "    ctx->fpr[%u] = ctx->fpr[%u];\n", inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FNEG:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_f64_from_bits(dolrecomp_f64_to_bits(ctx->fpr[%u]) ^ 0x8000000000000000ull);\n",
                inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FABS:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_f64_from_bits(dolrecomp_f64_to_bits(ctx->fpr[%u]) & 0x7FFFFFFFFFFFFFFFull);\n",
                inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FNABS:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_f64_from_bits(dolrecomp_f64_to_bits(ctx->fpr[%u]) | 0x8000000000000000ull);\n",
                inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FRSP:
        fprintf(out, "    ppc_frsp(ctx, %u, %u);\n", inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FSEL:
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->fpr[%u] = (ctx->fpr[%u] >= 0.0) ? ctx->fpr[%u] : ctx->fpr[%u];\n",
                inst->rD, inst->rA, inst->rC, inst->rB);
        if (inst->rc) {
            emit_set_cr1_from_fpscr(out);
        }
        fprintf(out, "    }\n");
        break;

    case PPC_OP_MTFSB0:
    case PPC_OP_MTFSB1:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 mask = 0x80000000u >> %u;\n", inst->rD);
        if (inst->op == PPC_OP_MTFSB0) {
            fprintf(out, "        if (%u != 1 && %u != 2) ctx->fpscr &= ~mask;\n",
                    inst->rD, inst->rD);
        } else {
            fprintf(out, "        if (%u != 1 && %u != 2) ctx->fpscr |= mask;\n",
                    inst->rD, inst->rD);
        }
        if (inst->rc) {
            emit_set_cr1_from_fpscr(out);
        }
        fprintf(out, "    }\n");
        break;

    case PPC_OP_MFFS:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_f64_from_bits(0xFFF8000000000000ull | ctx->fpscr);\n", inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_MCRFS: {
        u32 shift = cr_field_shift(inst->crfS);
        u32 dst_shift = cr_field_shift(inst->crfD);
        fprintf(out, "    {\n");
        fprintf(out, "        u32 field = (ctx->fpscr >> %u) & 0xFu;\n", shift);
        fprintf(out, "        ctx->fpscr &= ~((0xFu << %u) & 0x83F80700u);\n", shift);
        fprintf(out, "        ppc_fpscr_updated(ctx);\n");
        fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (field << %u);\n", dst_shift, dst_shift);
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_MTFSFI: {
        u32 shift = cr_field_shift(inst->crfD);
        fprintf(out, "    ctx->fpscr = (ctx->fpscr & ~(0xFu << %u)) | (0x%Xu << %u);\n",
                shift, inst->imm, shift);
        fprintf(out, "    ppc_fpscr_updated(ctx);\n");
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;
    }

    case PPC_OP_MTFSF:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 mask = 0;\n");
        fprintf(out, "        for (u32 i = 0; i < 8; i++) if (0x%02Xu & (1u << i)) mask |= 0xFu << (i * 4);\n", inst->fm);
        fprintf(out, "        u32 source = (u32)dolrecomp_f64_to_bits(ctx->fpr[%u]);\n", inst->rB);
        fprintf(out, "        ctx->fpscr = (ctx->fpscr & ~mask) | (source & mask);\n");
        fprintf(out, "        ppc_fpscr_updated(ctx);\n");
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_PS_ADD:
        fprintf(out, "    ppc_ps_add_op(ctx, %u, %u, %u);\n",
                inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_SUB:
        fprintf(out, "    ppc_ps_sub_op(ctx, %u, %u, %u);\n",
                inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MUL:
        fprintf(out, "    ppc_ps_mul_op(ctx, %u, %u, %u);\n",
                inst->rD, inst->rA, inst->rC);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_DIV:
        fprintf(out, "    ppc_ps_div_op(ctx, %u, %u, %u);\n",
                inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_RES:
        fprintf(out, "    ppc_ps_res_op(ctx, %u, %u);\n", inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_RSQRTE:
        fprintf(out, "    ppc_ps_rsqrte_op(ctx, %u, %u);\n", inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MADD:
    case PPC_OP_PS_MSUB:
    case PPC_OP_PS_NMADD:
    case PPC_OP_PS_NMSUB:
        fprintf(out, "    ppc_ps_madd_op(ctx, %u, %u, %u, %u, %s, %s);\n",
                inst->rD, inst->rA, inst->rC, inst->rB,
                (inst->op == PPC_OP_PS_MSUB || inst->op == PPC_OP_PS_NMSUB) ?
                    "true" : "false",
                (inst->op == PPC_OP_PS_NMADD || inst->op == PPC_OP_PS_NMSUB) ?
                    "true" : "false");
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_NEG:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->fpr[%u]) ^ 0x80000000u);\n",
                inst->rD, inst->rB);
        fprintf(out, "    ctx->ps1[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->ps1[%u]) ^ 0x80000000u);\n",
                inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_ABS:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->fpr[%u]) & 0x7FFFFFFFu);\n",
                inst->rD, inst->rB);
        fprintf(out, "    ctx->ps1[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->ps1[%u]) & 0x7FFFFFFFu);\n",
                inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_NABS:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->fpr[%u]) | 0x80000000u);\n",
                inst->rD, inst->rB);
        fprintf(out, "    ctx->ps1[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->ps1[%u]) | 0x80000000u);\n",
                inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MR:
        fprintf(out, "    ctx->fpr[%u] = ctx->fpr[%u];\n", inst->rD, inst->rB);
        fprintf(out, "    ctx->ps1[%u] = ctx->ps1[%u];\n", inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_SUM0:
        fprintf(out, "    ppc_ps_sum0(ctx, %u, %u, %u, %u);\n",
                inst->rD, inst->rA, inst->rC, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_SUM1:
        fprintf(out, "    ppc_ps_sum1(ctx, %u, %u, %u, %u);\n",
                inst->rD, inst->rA, inst->rC, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MULS0:
        fprintf(out, "    ppc_ps_muls0(ctx, %u, %u, %u);\n",
                inst->rD, inst->rA, inst->rC);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MULS1:
        fprintf(out, "    ppc_ps_muls1(ctx, %u, %u, %u);\n",
                inst->rD, inst->rA, inst->rC);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MADDS0:
        fprintf(out, "    ppc_ps_madds0(ctx, %u, %u, %u, %u);\n",
                inst->rD, inst->rA, inst->rC, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MADDS1:
        fprintf(out, "    ppc_ps_madds1(ctx, %u, %u, %u, %u);\n",
                inst->rD, inst->rA, inst->rC, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MERGE00:
        emit_ps_merge(out, inst, false, false);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MERGE01:
        emit_ps_merge(out, inst, false, true);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MERGE10:
        emit_ps_merge(out, inst, true, false);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MERGE11:
        emit_ps_merge(out, inst, true, true);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_CMPU0:
    case PPC_OP_PS_CMPO0:
    case PPC_OP_PS_CMPU1:
    case PPC_OP_PS_CMPO1: {
        bool lane1 = inst->op == PPC_OP_PS_CMPU1 || inst->op == PPC_OP_PS_CMPO1;
        bool ordered = inst->op == PPC_OP_PS_CMPO0 || inst->op == PPC_OP_PS_CMPO1;
        const char* bank = lane1 ? "ps1" : "fpr";
        fprintf(out, "    ppc_fcmp(ctx, %u, ctx->%s[%u], ctx->%s[%u], %s);\n",
                inst->crfD, bank, inst->rA, bank, inst->rB,
                ordered ? "true" : "false");
        break;
    }

    case PPC_OP_PS_SEL:
        fprintf(out, "    ctx->fpr[%u] = ((f32)ctx->fpr[%u] >= 0.0f) ? ctx->fpr[%u] : ctx->fpr[%u];\n",
                inst->rD, inst->rA, inst->rC, inst->rB);
        fprintf(out, "    ctx->ps1[%u] = ((f32)ctx->ps1[%u] >= 0.0f) ? ctx->ps1[%u] : ctx->ps1[%u];\n",
                inst->rD, inst->rA, inst->rC, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FCMPU:
    case PPC_OP_FCMPO:
        emit_fcompare(out, inst);
        break;

    case PPC_OP_LWZ:  emit_load(out, inst, RD32E, false); break;
    case PPC_OP_LWZU: emit_load(out, inst, RD32E, true); break;
    case PPC_OP_LBZ:  emit_load(out, inst, RD8E, false); break;
    case PPC_OP_LBZU: emit_load(out, inst, RD8E, true); break;
    case PPC_OP_LHZ:  emit_load(out, inst, RD16E, false); break;
    case PPC_OP_LHZU: emit_load(out, inst, RD16E, true); break;
    case PPC_OP_LHA:  emit_load(out, inst, RD16SE, false); break;
    case PPC_OP_LHAU: emit_load(out, inst, RD16SE, true); break;

    case PPC_OP_LWZX:  emit_loadx(out, inst, RD32E, false); break;
    case PPC_OP_LWZUX: emit_loadx(out, inst, RD32E, true); break;
    case PPC_OP_LBZX:  emit_loadx(out, inst, RD8E, false); break;
    case PPC_OP_LBZUX: emit_loadx(out, inst, RD8E, true); break;
    case PPC_OP_LHZX:  emit_loadx(out, inst, RD16E, false); break;
    case PPC_OP_LHZUX: emit_loadx(out, inst, RD16E, true); break;
    case PPC_OP_LHAX:  emit_loadx(out, inst, RD16SE, false); break;
    case PPC_OP_LHAUX: emit_loadx(out, inst, RD16SE, true); break;
    case PPC_OP_LWBRX: emit_loadx(out, inst,
        mem_rd_expr("bswap32(mem_read32(ctx, ea))", "mem_read32le_direct(ctx, ea)"), false); break;
    case PPC_OP_LHBRX: emit_loadx(out, inst,
        mem_rd_expr("bswap16(mem_read16(ctx, ea))", "mem_read16le_direct(ctx, ea)"), false); break;

    case PPC_OP_LFS:   emit_fload(out, inst, true,  false); break;
    case PPC_OP_LFSU:  emit_fload(out, inst, true,  true); break;
    case PPC_OP_LFD:   emit_fload(out, inst, false, false); break;
    case PPC_OP_LFDU:  emit_fload(out, inst, false, true); break;

    case PPC_OP_LFSX:  emit_floadx(out, inst, true,  false); break;
    case PPC_OP_LFSUX: emit_floadx(out, inst, true,  true); break;
    case PPC_OP_LFDX:  emit_floadx(out, inst, false, false); break;
    case PPC_OP_LFDUX: emit_floadx(out, inst, false, true); break;

    case PPC_OP_PSQ_L:   emit_psq_load(out, inst, false, false); break;
    case PPC_OP_PSQ_LU:  emit_psq_load(out, inst, false, true); break;
    case PPC_OP_PSQ_LX:  emit_psq_load(out, inst, true,  false); break;
    case PPC_OP_PSQ_LUX: emit_psq_load(out, inst, true,  true); break;

    case PPC_OP_STW:  emit_store(out, inst, WR32, "u32", false); break;
    case PPC_OP_STWU: emit_store(out, inst, WR32, "u32", true); break;
    case PPC_OP_STB:  emit_store(out, inst, WR8, "u8", false); break;
    case PPC_OP_STBU: emit_store(out, inst, WR8, "u8", true); break;
    case PPC_OP_STH:  emit_store(out, inst, WR16, "u16", false); break;
    case PPC_OP_STHU: emit_store(out, inst, WR16, "u16", true); break;

    case PPC_OP_STWX:  emit_storex(out, inst, WR32, "u32", false); break;
    case PPC_OP_STWUX: emit_storex(out, inst, WR32, "u32", true); break;
    case PPC_OP_STBX:  emit_storex(out, inst, WR8, "u8", false); break;
    case PPC_OP_STBUX: emit_storex(out, inst, WR8, "u8", true); break;
    case PPC_OP_STHX:  emit_storex(out, inst, WR16, "u16", false); break;
    case PPC_OP_STHUX: emit_storex(out, inst, WR16, "u16", true); break;

    case PPC_OP_STFS:   emit_fstore(out, inst, true,  false); break;
    case PPC_OP_STFSU:  emit_fstore(out, inst, true,  true); break;
    case PPC_OP_STFD:   emit_fstore(out, inst, false, false); break;
    case PPC_OP_STFDU:  emit_fstore(out, inst, false, true); break;

    case PPC_OP_STFSX:  emit_fstorex(out, inst, true,  false); break;
    case PPC_OP_STFSUX: emit_fstorex(out, inst, true,  true); break;
    case PPC_OP_STFDX:  emit_fstorex(out, inst, false, false); break;
    case PPC_OP_STFDUX: emit_fstorex(out, inst, false, true); break;

    case PPC_OP_PSQ_ST:   emit_psq_store(out, inst, false, false); break;
    case PPC_OP_PSQ_STU:  emit_psq_store(out, inst, false, true); break;
    case PPC_OP_PSQ_STX:  emit_psq_store(out, inst, true,  false); break;
    case PPC_OP_PSQ_STUX: emit_psq_store(out, inst, true,  true); break;

    case PPC_OP_STWBRX:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n");
        if (direct_mem_lowering())
            fprintf(out, "        mem_write32le_direct(ctx, ea, ctx->gpr[%u]);\n", inst->rS);
        else
            fprintf(out, "        mem_write32(ctx, ea, bswap32(ctx->gpr[%u]));\n", inst->rS);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_STHBRX:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n");
        if (direct_mem_lowering())
            fprintf(out, "        mem_write16le_direct(ctx, ea, (u16)ctx->gpr[%u]);\n", inst->rS);
        else
            fprintf(out, "        mem_write16(ctx, ea, bswap16((u16)ctx->gpr[%u]));\n", inst->rS);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_LSWI:
    case PPC_OP_LSWX: {
        u32 count = inst->op == PPC_OP_LSWI ? (inst->nb ? inst->nb : 32u) : 0u;
        fprintf(out, "    {\n");
        if (inst->op == PPC_OP_LSWX) {
            fprintf(out, "        u32 ea = ctx->gpr[%u];\n", inst->rB);
            if (inst->rA)
                fprintf(out, "        ea += ctx->gpr[%u];\n", inst->rA);
            fprintf(out, "        u32 count = ctx->xer & 0x7Fu;\n");
            fprintf(out, "        u32 reg_count = (count + 3u) / 4u;\n");
            fprintf(out, "        for (u32 r = 0; r < reg_count; r++) {\n");
            fprintf(out, "            u32 reg = (%uu + r) & 31u;\n", inst->rD);
            fprintf(out, "            if (reg == %uu || reg == %uu) {\n", inst->rA, inst->rB);
            fprintf(out, "                ppc_program_exception(ctx, PPC_PROGRAM_ILLEGAL, 0x%08Xu);\n",
                    inst->address);
            fprintf(out, "                return;\n");
            fprintf(out, "            }\n");
            fprintf(out, "        }\n");
        } else {
            if (inst->rA) fprintf(out, "        u32 ea = ctx->gpr[%u];\n", inst->rA);
            else fprintf(out, "        u32 ea = 0u;\n");
            fprintf(out, "        u32 count = %uu;\n", count);
        }
        fprintf(out, "        for (u32 n = 0; n < count; n++) {\n");
        fprintf(out, "            u32 reg = (%uu + n / 4u) & 31u;\n", inst->rD);
        fprintf(out, "            if ((n & 3u) == 0) ctx->gpr[reg] = 0;\n");
        fprintf(out, "            ctx->gpr[reg] |= (u32)%s << (24u - 8u * (n & 3u));\n",
            mem_rd_expr("mem_read8(ctx, ea + n)", "mem_read8_direct(ctx, ea + n)"));
        fprintf(out, "        }\n");
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_STSWI:
    case PPC_OP_STSWX: {
        u32 count = inst->op == PPC_OP_STSWI ? (inst->nb ? inst->nb : 32u) : 0u;
        fprintf(out, "    {\n");
        if (inst->op == PPC_OP_STSWX) {
            fprintf(out, "        u32 ea = ctx->gpr[%u]", inst->rB);
            if (inst->rA) fprintf(out, " + ctx->gpr[%u]", inst->rA);
            fprintf(out, ";\n        u32 count = ctx->xer & 0x7Fu;\n");
        } else {
            if (inst->rA) fprintf(out, "        u32 ea = ctx->gpr[%u];\n", inst->rA);
            else fprintf(out, "        u32 ea = 0u;\n");
            fprintf(out, "        u32 count = %uu;\n", count);
        }
        fprintf(out, "        for (u32 n = 0; n < count; n++) {\n");
        fprintf(out, "            u32 reg = (%uu + n / 4u) & 31u;\n", inst->rS);
        fprintf(out, "            u8 value = (u8)(ctx->gpr[reg] >> (24u - 8u * (n & 3u)));\n");
        fprintf(out, "            %s(ctx, ea + n, value);\n",
            mem_rd_expr("mem_write8", "mem_write8_direct"));
        fprintf(out, "        }\n");
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_LWARX:
        fprintf(out, "    {\n        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n        ctx->gpr[%u] = %s;\n", inst->rD,
                mem_rd_expr("mem_read32(ctx, ea)", "mem_read32_direct(ctx, ea)"));
        fprintf(out, "        ctx->reserve_addr = ea;\n        ctx->reserve_valid = true;\n    }\n");
        break;

    case PPC_OP_STWCX:
        fprintf(out, "    {\n        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n        bool success = ctx->reserve_valid && ea == ctx->reserve_addr;\n");
        fprintf(out, "        if (success) { %s(ctx, ea, ctx->gpr[%u]); ctx->reserve_valid = false; }\n",
                mem_rd_expr("mem_write32", "mem_write32_direct"), inst->rS);
        fprintf(out, "        ctx->cr = (ctx->cr & 0x0FFFFFFFu) | ((success ? 2u : 0u) << 28) | ((ctx->xer >> 3) & 0x10000000u);\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_STFIWX:
        fprintf(out, "    {\n        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n        %s(ctx, ea, (u32)dolrecomp_f64_to_bits(ctx->fpr[%u]));\n    }\n",
                mem_rd_expr("mem_write32", "mem_write32_direct"), inst->rS);
        break;

    case PPC_OP_DCBZ:
        emit_dcbz(out, inst);
        break;

    case PPC_OP_DCBZ_L:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n");
        fprintf(out, "        ppc_dcbz_l(ctx, ea, 0x%08Xu);\n", emit_guest_addr(inst->address));
        fprintf(out, "        if (ctx->exception) return;\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_DCBST:
    case PPC_OP_DCBF:
    case PPC_OP_DCBI:
    case PPC_OP_ICBI:
        fprintf(out, "    ppc_fallback_instruction(ctx, 0x%08Xu, 0x%08Xu);\n",
                inst->raw, emit_guest_addr(inst->address));
        emit_fallback_return(out, inst, func_end, per_inst_labels);
        break;

    case PPC_OP_DCBTST:
    case PPC_OP_DCBT:
        fprintf(out, "    (void)ctx;\n");
        break;

    case PPC_OP_LMW:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_dform_ea(out, inst->rA, inst->simm, false);
        fprintf(out, ";\n");
        fprintf(out, "        for (u32 r = %u; r < 32; r++, ea += 4) ctx->gpr[r] = %s;\n",
                inst->rD, mem_rd_expr("mem_read32(ctx, ea)", "mem_read32_direct(ctx, ea)"));
        fprintf(out, "    }\n");
        break;

    case PPC_OP_STMW:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_dform_ea(out, inst->rA, inst->simm, false);
        fprintf(out, ";\n");
        fprintf(out, "        for (u32 r = %u; r < 32; r++, ea += 4) %s(ctx, ea, ctx->gpr[r]);\n",
                inst->rS, mem_rd_expr("mem_write32", "mem_write32_direct"));
        fprintf(out, "    }\n");
        break;

    case PPC_OP_B:
        fprintf(out, "    {\n");
        emit_direct_branch(out, inst,
                           branch_target_is_local(func_start, func_end, inst->branch_target),
                           direct_backedge, func_start, func_end);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_BC:
        fprintf(out, "    {\n");
        emit_branch_condition(out, inst->bo, inst->bi);
        fprintf(out, "        if (ctr_ok && cr_ok) {\n");
        emit_direct_branch(out, inst,
                           branch_target_is_local(func_start, func_end, inst->branch_target),
                           direct_backedge, func_start, func_end);
        fprintf(out, "        }\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_BCLR:
        emit_dynamic_branch(out, inst, "ctx->lr & ~3u",
                            route_local_returns, func_start);
        break;

    case PPC_OP_BCCTR:
        emit_dynamic_branch(out, inst, "ctx->ctr & ~3u", false, func_start);
        break;

    case PPC_OP_TWI:
        fprintf(out, "    if (ppc_trap_condition(%uu, ctx->gpr[%u], (u32)(s32)%d)) {\n",
                inst->to, inst->rA, (int)inst->simm);
        fprintf(out, "        ppc_program_exception(ctx, PPC_PROGRAM_TRAP, 0x%08Xu);\n", emit_guest_addr(inst->address));
        fprintf(out, "        return;\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_TW:
        fprintf(out, "    if (ppc_trap_condition(%uu, ctx->gpr[%u], ctx->gpr[%u])) {\n",
                inst->to, inst->rA, inst->rB);
        fprintf(out, "        ppc_program_exception(ctx, PPC_PROGRAM_TRAP, 0x%08Xu);\n", emit_guest_addr(inst->address));
        fprintf(out, "        return;\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SC:
        fprintf(out, "    ppc_system_call_exception(ctx, 0x%08Xu);\n", emit_guest_addr(inst->address));
        fprintf(out, "    return;\n");
        break;

    case PPC_OP_RFI:
        fprintf(out, "    ppc_rfi(ctx, 0x%08Xu);\n", emit_guest_addr(inst->address));
        fprintf(out, "    return;\n");
        break;

    case PPC_OP_CRAND:  emit_cr_logical(out, inst, "a & b"); break;
    case PPC_OP_CRANDC: emit_cr_logical(out, inst, "a & ~b"); break;
    case PPC_OP_CREQV:  emit_cr_logical(out, inst, "~(a ^ b)"); break;
    case PPC_OP_CRNAND: emit_cr_logical(out, inst, "~(a & b)"); break;
    case PPC_OP_CRNOR:  emit_cr_logical(out, inst, "~(a | b)"); break;
    case PPC_OP_CROR:   emit_cr_logical(out, inst, "a | b"); break;
    case PPC_OP_CRORC:  emit_cr_logical(out, inst, "a | ~b"); break;
    case PPC_OP_CRXOR:  emit_cr_logical(out, inst, "a ^ b"); break;

    case PPC_OP_MCRF: {
        u32 dst_shift = cr_field_shift(inst->crfD);
        u32 src_shift = cr_field_shift(inst->crfS);
        fprintf(out, "    {\n");
        fprintf(out, "        u32 bits = (ctx->cr >> %u) & 0xFu;\n", src_shift);
        fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (bits << %u);\n",
                dst_shift, dst_shift);
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_MCRXR: {
        u32 dst_shift = cr_field_shift(inst->crfD);
        fprintf(out, "    {\n");
        fprintf(out, "        u32 bits = (ctx->xer >> 28) & 0xFu;\n");
        fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (bits << %u);\n",
                dst_shift, dst_shift);
        fprintf(out, "        ctx->xer &= ~0xE0000000u;\n");
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_MFCR:
        fprintf(out, "    ctx->gpr[%u] = ctx->cr;\n", inst->rD);
        break;

    case PPC_OP_MTCRF: {
        u32 mask = 0;
        for (u32 crf = 0; crf < 8; crf++) {
            if (inst->crm & (0x80u >> crf))
                mask |= 0xFu << cr_field_shift((u8)crf);
        }
        if (mask) {
            fprintf(out, "    ctx->cr = (ctx->cr & ~0x%08Xu) | (ctx->gpr[%u] & 0x%08Xu);\n",
                    mask, inst->rS, mask);
        } else {
            fprintf(out, "    // mtcrf mask selects no CR fields\n");
        }
        break;
    }

    case PPC_OP_MFMSR:
        fprintf(out, "    ctx->gpr[%u] = ctx->msr;\n", inst->rD);
        break;

    case PPC_OP_MTMSR:
        fprintf(out, "    ctx->msr = ctx->gpr[%u];\n", inst->rS);
        break;

    case PPC_OP_MFSR:
        fprintf(out, "    ctx->gpr[%u] = ctx->sr[%u];\n", inst->rD, inst->sr);
        break;

    case PPC_OP_MFSRIN:
        fprintf(out, "    ctx->gpr[%u] = ctx->sr[(ctx->gpr[%u] >> 28) & 0xFu];\n",
                inst->rD, inst->rB);
        break;

    case PPC_OP_MTSR:
        fprintf(out, "    ctx->sr[%u] = ctx->gpr[%u];\n", inst->sr, inst->rS);
        break;

    case PPC_OP_MTSRIN:
        fprintf(out, "    ctx->sr[(ctx->gpr[%u] >> 28) & 0xFu] = ctx->gpr[%u];\n",
                inst->rB, inst->rS);
        break;

    case PPC_OP_MFTB:
        fprintf(out, "    ctx->gpr[%u] = ppc_mftb(ctx, %uu, 0x%08Xu);\n",
                inst->rD, inst->spr, inst->address);
        fprintf(out, "    if (ctx->exception) return;\n");
        break;

    case PPC_OP_MFSPR:
        switch (inst->spr) {
        case 1: fprintf(out, "    ctx->gpr[%u] = ctx->xer;\n", inst->rD); break;
        case 8: fprintf(out, "    ctx->gpr[%u] = ctx->lr;\n", inst->rD); break;
        case 9: fprintf(out, "    ctx->gpr[%u] = ctx->ctr;\n", inst->rD); break;
        case 26: fprintf(out, "    ctx->gpr[%u] = ctx->srr0;\n", inst->rD); break;
        case 27: fprintf(out, "    ctx->gpr[%u] = ctx->srr1;\n", inst->rD); break;
        case 268:
        case 269:
            fprintf(out, "    ctx->gpr[%u] = ppc_mftb(ctx, %uu, 0x%08Xu);\n",
                    inst->rD, inst->spr, inst->address);
            fprintf(out, "    if (ctx->exception) return;\n");
            break;
        case 912: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[0];\n", inst->rD); break;
        case 913: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[1];\n", inst->rD); break;
        case 914: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[2];\n", inst->rD); break;
        case 915: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[3];\n", inst->rD); break;
        case 916: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[4];\n", inst->rD); break;
        case 917: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[5];\n", inst->rD); break;
        case 918: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[6];\n", inst->rD); break;
        case 919: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[7];\n", inst->rD); break;
        case 282: fprintf(out, "    ctx->gpr[%u] = ctx->ear;\n", inst->rD); break;
        case 920: fprintf(out, "    ctx->gpr[%u] = ctx->hid2;\n", inst->rD); break;
        default:
            fprintf(out, "    ppc_fallback_instruction(ctx, 0x%08Xu, 0x%08Xu);\n",
                    inst->raw, emit_guest_addr(inst->address));
            emit_fallback_return(out, inst, func_end, per_inst_labels);
            break;
        }
        break;

    case PPC_OP_MTSPR:
        switch (inst->spr) {
        case 1: fprintf(out, "    ctx->xer = ctx->gpr[%u];\n", inst->rS); break;
        case 8: fprintf(out, "    ctx->lr = ctx->gpr[%u];\n", inst->rS); break;
        case 9: fprintf(out, "    ctx->ctr = ctx->gpr[%u];\n", inst->rS); break;
        case 26: fprintf(out, "    ctx->srr0 = ctx->gpr[%u];\n", inst->rS); break;
        case 27: fprintf(out, "    ctx->srr1 = ctx->gpr[%u];\n", inst->rS); break;
        case 282: fprintf(out, "    ctx->ear = ctx->gpr[%u];\n", inst->rS); break;
        case 912: fprintf(out, "    ctx->gqr[0] = ctx->gpr[%u];\n", inst->rS); break;
        case 913: fprintf(out, "    ctx->gqr[1] = ctx->gpr[%u];\n", inst->rS); break;
        case 914: fprintf(out, "    ctx->gqr[2] = ctx->gpr[%u];\n", inst->rS); break;
        case 915: fprintf(out, "    ctx->gqr[3] = ctx->gpr[%u];\n", inst->rS); break;
        case 916: fprintf(out, "    ctx->gqr[4] = ctx->gpr[%u];\n", inst->rS); break;
        case 917: fprintf(out, "    ctx->gqr[5] = ctx->gpr[%u];\n", inst->rS); break;
        case 918: fprintf(out, "    ctx->gqr[6] = ctx->gpr[%u];\n", inst->rS); break;
        case 919: fprintf(out, "    ctx->gqr[7] = ctx->gpr[%u];\n", inst->rS); break;
        case 920: fprintf(out, "    ctx->hid2 = ctx->gpr[%u];\n", inst->rS); break;
        default:
            fprintf(out, "    ppc_fallback_instruction(ctx, 0x%08Xu, 0x%08Xu);\n",
                    inst->raw, emit_guest_addr(inst->address));
            emit_fallback_return(out, inst, func_end, per_inst_labels);
            break;
        }
        break;

    case PPC_OP_TLBIE:
        fprintf(out, "    ppc_tlbie(ctx, ctx->gpr[%u], 0x%08Xu);\n", inst->rB, inst->address);
        fprintf(out, "    if (ctx->exception) return;\n");
        break;

    case PPC_OP_SYNC:
    case PPC_OP_EIEIO:
    case PPC_OP_ISYNC:
    case PPC_OP_TLBSYNC:
        fprintf(out, "    ppc_memory_fence();\n");
        break;

    case PPC_OP_ECIWX:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n");
        fprintf(out, "        u32 value = ppc_eciwx(ctx, ea, 0x%08Xu);\n", inst->address);
        fprintf(out, "        if (ctx->exception) return;\n");
        fprintf(out, "        ctx->gpr[%u] = value;\n", inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ECOWX:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n");
        fprintf(out, "        ppc_ecowx(ctx, ea, ctx->gpr[%u], 0x%08Xu);\n",
                inst->rS, inst->address);
        fprintf(out, "        if (ctx->exception) return;\n");
        fprintf(out, "    }\n");
        break;

    default:
        fprintf(out, "    ppc_fallback_instruction(ctx, 0x%08Xu, 0x%08Xu);\n",
                inst->raw, emit_guest_addr(inst->address));
        emit_fallback_return(out, inst, func_end, per_inst_labels);
        break;
    }

    fprintf(out, "\n");
}

void emit_instruction(FILE* out, const PPCInst* inst) {
    emit_instruction_with_range(out, inst, 0, (u32)-1, false, false, false);
}

static void emit_counted_loop(FILE* out, const PPCInst* insts,
                              const CFunctionCFG* cfg, u32 function_address,
                              u32 function_end, u32 first, u32 last) {
    u32 loop_address = insts[first].address;
    u32 continuation = insts[last].address + 4u;

    fprintf(out, "static void loop_%08X(CPUState* ctx) {\n",
            emit_guest_addr(loop_address));
    fprintf(out, "label_%08X:\n", emit_guest_addr(loop_address));
    fprintf(out, "    ctx->downcount -= %u;\n", cfg->block_cycles[first]);
    for (u32 i = first; i <= last; ++i) {
        if (cfg->materialize_pc[i])
            fprintf(out, "    ctx->pc = 0x%08Xu;\n",
                    emit_guest_addr(insts[i].address));
        emit_instruction_with_range(out, &insts[i], function_address,
                                    function_end, i == last, false, false);
    }
    fprintf(out, "    ctx->pc = 0x%08Xu;\n", emit_guest_addr(continuation));
    fprintf(out, "}\n\n");
}

bool emit_function(FILE* out, const PPCInst* insts, u32 count, u32 func_addr) {
    u32 func_end = func_addr + count * 4u;
    CFunctionCFG cfg;
    if (!c_function_cfg_build(&cfg, insts, count, func_addr)) {
        fprintf(stderr, "error: out of memory while analyzing function %08X\n",
                func_addr);
        return false;
    }
    // DOLRECOMP_C_LOCAL_RETURNS=0 sends every blr back through the dispatcher
    // instead of routing it inside the function.
    bool has_local_returns = false;
    for (u32 i = 0; i < count; ++i)
        has_local_returns |= cfg.return_targets[i] != 0;

    for (u32 i = 0; i < count; ++i) {
        if (cfg.loop_ends[i] != UINT32_MAX)
            emit_counted_loop(out, insts, &cfg, func_addr, func_end, i,
                              cfg.loop_ends[i]);
    }

    fprintf(out, "void func_%08X(CPUState* ctx) {\n", emit_guest_addr(func_addr));
    fprintf(out, "    switch (ctx->pc) {\n");
    for (u32 i = 0; i < count; i++) {
        fprintf(out, "    case 0x%08Xu: goto label_%08X;\n",
                emit_guest_addr(insts[i].address),
                emit_guest_addr(insts[i].address));
    }
    fprintf(out, "    default: return;\n");
    fprintf(out, "    }\n");

    for (u32 i = 0; i < count; i++) {
        fprintf(out, "label_%08X:\n", emit_guest_addr(insts[i].address));
        if (cfg.loop_ends[i] != UINT32_MAX) {
            u32 continuation = insts[cfg.loop_ends[i]].address + 4u;
            fprintf(out, "    loop_%08X(ctx);\n",
                    emit_guest_addr(insts[i].address));
            if (continuation < func_end) {
                fprintf(out, "    if (ctx->pc == 0x%08Xu) goto label_%08X;\n",
                        emit_guest_addr(continuation),
                        emit_guest_addr(continuation));
            }
            fprintf(out, "    return;\n");
            continue;
        }
        if (cfg.materialize_pc[i])
            fprintf(out, "    ctx->pc = 0x%08Xu;\n",
                    emit_guest_addr(insts[i].address));
        if (cfg.leaders[i] && cfg.block_cycles[i] != 0)
            fprintf(out, "    ctx->downcount -= %u;\n", cfg.block_cycles[i]);
        emit_instruction_with_range(
            out, &insts[i], func_addr, func_end,
            c_function_cfg_can_loop_directly(&cfg, insts, func_addr, i),
            has_local_returns, true);
    }

    fprintf(out, "    ctx->pc = 0x%08Xu;\n", emit_guest_addr(func_end));
    if (has_local_returns) {
        fprintf(out, "    return;\n");
        fprintf(out, "return_dispatch_%08X:\n", emit_guest_addr(func_addr));
        fprintf(out, "    if (ctx->downcount <= -(s64)DOLRECOMP_C_LOOP_CYCLE_BUDGET) return;\n");
        fprintf(out, "    switch (ctx->pc) {\n");
        for (u32 i = 0; i < count; ++i) {
            if (cfg.return_targets[i]) {
                fprintf(out, "    case 0x%08Xu: goto label_%08X;\n",
                        emit_guest_addr(insts[i].address),
                        emit_guest_addr(insts[i].address));
            }
        }
        fprintf(out, "    default: return;\n");
        fprintf(out, "    }\n");
    }
    fprintf(out, "}\n\n");
    c_function_cfg_destroy(&cfg);
    return true;
}
