//! Structural fingerprinting of extracted functions.
//!
//! Each function gets two FNV-1a hashes: a *skeleton* hash that sees only
//! shape (fact kinds and counts, names discarded) and an *exact* hash that also
//! folds in method and type names. Equal skeleton hashes across files signal
//! parametric duplicates; equal exact hashes signal copy-paste.

use crate::ir::facts::{ControlFlowKind, FileIr, FnFingerprint};

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a hash: fold bytes into a running `u64` state.
fn fnv1a_bytes(state: u64, bytes: &[u8]) -> u64 {
    const PRIME: u64 = 0x0100_0000_01b3;
    bytes
        .iter()
        .fold(state, |h, &b| (h ^ u64::from(b)).wrapping_mul(PRIME))
}

/// FNV-1a hash a `usize` value.
fn fnv1a_usize(state: u64, value: usize) -> u64 {
    fnv1a_bytes(state, &value.to_le_bytes())
}

/// FNV-1a hash a boolean value.
fn fnv1a_bool(state: u64, value: bool) -> u64 {
    fnv1a_bytes(state, &[u8::from(value)])
}

/// FNV-1a hash a discriminant (as its `u8` index).
fn fnv1a_discriminant(state: u64, kind: ControlFlowKind) -> u64 {
    let tag = match kind {
        ControlFlowKind::If => 0u8,
        ControlFlowKind::Match => 1,
        ControlFlowKind::ForLoop => 2,
        ControlFlowKind::WhileLoop => 3,
        ControlFlowKind::Loop => 4,
        ControlFlowKind::Closure => 5,
    };
    fnv1a_bytes(state, &[tag])
}

/// Per-function hash accumulators, held as parallel arrays indexed by function.
///
/// Each fact array is folded in with a single pass, so no intermediate bucket
/// table is ever built. Fold order is part of the hash and must not change
/// without invalidating stored fingerprints.
struct FingerprintAccum {
    skeleton: Vec<u64>,
    exact: Vec<u64>,
    method_count: Vec<usize>,
    binding_count: Vec<usize>,
    type_ref_count: Vec<usize>,
    fact_count: Vec<usize>,
}

impl FingerprintAccum {
    /// Seed both hashes from each function's signature (param count + whether
    /// it returns), the only signature detail shared by skeleton and exact.
    fn seed(ir: &FileIr) -> Self {
        let fn_count = ir.functions.len();
        let mut skeleton: Vec<u64> = Vec::with_capacity(fn_count);
        let mut exact: Vec<u64> = Vec::with_capacity(fn_count);

        for func in ir.functions.iter() {
            let mut h = FNV_OFFSET_BASIS;
            h = fnv1a_usize(h, func.params.len());
            h = fnv1a_bool(h, func.return_type.is_some());
            skeleton.push(h);
            exact.push(h);
        }

        Self {
            skeleton,
            exact,
            method_count: vec![0usize; fn_count],
            binding_count: vec![0usize; fn_count],
            type_ref_count: vec![0usize; fn_count],
            fact_count: vec![0usize; fn_count],
        }
    }

    /// Control flow: both hashes take the discriminant tag, since shape is the
    /// signal regardless of naming.
    fn fold_control_flow(&mut self, ir: &FileIr) {
        for fact in ir.control_flow.iter() {
            let Some(fn_idx) = fact.containing_fn else {
                continue;
            };
            self.skeleton[fn_idx] = fnv1a_discriminant(self.skeleton[fn_idx], fact.kind);
            self.exact[fn_idx] = fnv1a_discriminant(self.exact[fn_idx], fact.kind);
            self.fact_count[fn_idx] += 1;
        }
    }

    /// Method calls: exact hash takes the name bytes, skeleton only counts.
    fn fold_method_calls(&mut self, ir: &FileIr) {
        for fact in ir.method_calls.iter() {
            let Some(fn_idx) = fact.containing_fn else {
                continue;
            };
            self.exact[fn_idx] = fnv1a_bytes(self.exact[fn_idx], fact.method_name.as_bytes());
            self.method_count[fn_idx] += 1;
            self.fact_count[fn_idx] += 1;
        }
    }

    /// Bindings contribute count only — names are noise for both hashes. The
    /// count folds into the exact hash here so it lands before type refs.
    fn fold_bindings(&mut self, ir: &FileIr) {
        for fact in ir.bindings.iter() {
            let Some(fn_idx) = fact.containing_fn else {
                continue;
            };
            self.binding_count[fn_idx] += 1;
            self.fact_count[fn_idx] += 1;
        }
        for (ex, &bc) in self.exact.iter_mut().zip(self.binding_count.iter()) {
            *ex = fnv1a_usize(*ex, bc);
        }
    }

    /// Type refs: exact hash takes the rendered text, skeleton only counts.
    fn fold_type_refs(&mut self, ir: &FileIr) {
        for fact in ir.type_refs.iter() {
            let Some(fn_idx) = fact.containing_fn else {
                continue;
            };
            self.exact[fn_idx] = fnv1a_bytes(self.exact[fn_idx], fact.text.as_bytes());
            self.type_ref_count[fn_idx] += 1;
            self.fact_count[fn_idx] += 1;
        }
    }

    /// Fold the counts the skeleton hash deliberately deferred, so that shape
    /// alone — not name content — closes it out.
    fn finish_skeleton(&mut self) {
        for i in 0..self.skeleton.len() {
            self.skeleton[i] = fnv1a_usize(self.skeleton[i], self.method_count[i]);
            self.skeleton[i] = fnv1a_usize(self.skeleton[i], self.binding_count[i]);
            self.skeleton[i] = fnv1a_usize(self.skeleton[i], self.type_ref_count[i]);
        }
    }

    fn into_fingerprints(self, ir: &FileIr) -> Box<[FnFingerprint]> {
        ir.functions
            .iter()
            .enumerate()
            .map(|(fn_index, func)| FnFingerprint {
                fn_index,
                name: Box::from(&*func.name),
                span: func.span,
                skeleton_hash: self.skeleton[fn_index],
                exact_hash: self.exact[fn_index],
                fact_count: self.fact_count[fn_index],
            })
            .collect()
    }
}

/// Compute structural fingerprints for all functions in the IR.
///
/// Each function gets a skeleton hash (structure-only, names normalized) and
/// an exact hash (includes method/type names). Downstream consumers use these
/// to detect copy-paste and parametric duplicates across files.
///
/// Uses per-function hash accumulators fed by single passes over each fact
/// array, avoiding intermediate bucket tables.
pub fn compute_fingerprints(ir: &FileIr) -> Box<[FnFingerprint]> {
    let mut accum = FingerprintAccum::seed(ir);
    accum.fold_control_flow(ir);
    accum.fold_method_calls(ir);
    accum.fold_bindings(ir);
    accum.fold_type_refs(ir);
    accum.finish_skeleton();
    accum.into_fingerprints(ir)
}
