use std::marker::PhantomData;
use std::sync::Arc;

struct BuilderBrand;

struct Handle<K> {
    brand: Arc<BuilderBrand>,
    index: u32,
    kind: PhantomData<fn() -> K>,
}

struct UnitKind;
struct DefinitionKind;
struct ReferenceKind;

type UnitHandle = Handle<UnitKind>;
type DefinitionHandle = Handle<DefinitionKind>;
type ReferenceHandle = Handle<ReferenceKind>;

struct CandidateInput {
    definition: DefinitionHandle,
}

fn same_builder(
    unit: UnitHandle,
    definition: DefinitionHandle,
    reference: ReferenceHandle,
) -> CandidateInput {
    let _ = (unit, reference);
    CandidateInput { definition }
}
