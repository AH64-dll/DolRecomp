#ifndef DOLRECOMP_EMITTER_H
#define DOLRECOMP_EMITTER_H

#include "../common/types.h"
#include "../frontend/decoder.h"
#include <stdio.h>

typedef enum {
    DOLRECOMP_CPU_GEKKO,
    DOLRECOMP_CPU_BROADWAY,
    DOLRECOMP_CPU_ESPRESSO,
} DolRecompCPU;

// Split C emitter used by the command-line recompiler.

// emit the boilerplate header (includes, typedefs, etc)
void emit_header(FILE* out);
void emit_header_for_cpu(FILE* out, DolRecompCPU cpu);

// Register chunk entries for the opt-in cross-chunk direct-call experiment.
// Direct calls bypass chassis dispatch checks and must not be enabled by a
// runtime that validates mutable guest code there. Call before worker emission;
// passing count == 0 restores the safe return-to-chassis form.
void emit_set_chunk_table(const u32* starts, u32 count);

// Register the inline host-call hook set (env DOLRECOMP_HOST_HOOKS): sorted
// ascending guest addresses that get a `ppc_host_call` dispatch emitted in
// front of the instruction body (before the fp gate, so a skipping hook
// bypasses it). Call before worker emission; count == 0 restores hook-free
// output. DOLRECOMP_HOST_HOOKS=0x800078C0,0x8003E370,...
void emit_set_host_hooks(const u32* addrs, u32 count);

// Register the GCC gpr save/restore stub ranges (env
// DOLRECOMP_GPR_STUBS=save_lo:save_hi,rest_lo:rest_hi, retail hex, *_hi is
// the stub's trailing blr). A `bl` into either range is emitted as the stub
// body inline instead of a chassis round trip. All zeros disables.
void emit_set_gpr_stub_ranges(u32 save_lo, u32 save_hi,
                              u32 rest_lo, u32 rest_hi);

// emit a single recompiled function as C code
bool emit_function(FILE* out, const PPCInst* insts, u32 count, u32 func_addr);

// emit a single instruction as C code
void emit_instruction(FILE* out, const PPCInst* inst);

// emit the boilerplate footer

// LRELOC P1: emit-time guest-address translation for second-bank batches.
// Call BEFORE any emission with [lo..hi] covering the batch's RETAIL span
// and delta = new_base - retail_base; passing delta 0 (default) disables.
void emit_set_guest_translation(u32 lo, u32 hi, u32 delta);
u32 emit_guest_addr(u32 addr);
// LRELOC P8: translate a composed 32-bit DATA literal (non-reloc constant,
// e.g. lis/addi self-pointer). Identity when off/out of span; counts hits.
u32 emit_guest_literal(u32 addr);
u32 emit_guest_literal_count(void);
void emit_footer(FILE* out);

#endif /* DOLRECOMP_EMITTER_H */
