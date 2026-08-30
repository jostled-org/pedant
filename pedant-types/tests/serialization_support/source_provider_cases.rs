//! The generic source-provider contract this crate publishes.
//!
//! Everything asserted here is a claim about the seam's *shape*: that it names
//! no root, no language, and no consuming crate, and that one implementor can
//! answer for two unrelated fact types with two unrelated typed errors. A
//! behavioral claim about a real provider belongs to the crate that owns the
//! parser, so nothing here reads a file.

use std::sync::Arc;

use pedant_types::{SourcePath, SourceProvider, SourceRecord};

/// The manifest that must name no consumer of this crate.
const MANIFEST: &str = include_str!("../../Cargo.toml");

/// The workspace manifest the consumer list is read from.
///
/// Read rather than restated: a hand-written list is one member behind the
/// workspace the moment a member is added, and the omission looks exactly like
/// a passing check. The hand-written list this replaced had already lost
/// `pedant`, which is every other member's root.
const WORKSPACE: &str = include_str!("../../../Cargo.toml");

/// This crate's own name, which is a member and never a consumer.
const SELF_NAME: &str = "pedant-types";

/// One fact type a provider can answer for.
#[derive(Debug, PartialEq, Eq)]
struct AlphaFacts {
    declarations: u32,
}

/// A second, unrelated fact type the same provider answers for.
#[derive(Debug, PartialEq, Eq)]
struct BetaFacts {
    imports: u32,
}

/// Why an alpha request states no record.
///
/// The incomplete arm carries the language's own inventory, which is the whole
/// reason the error is per-language: a shared cause could not say what an alpha
/// walk had reached when it stopped.
#[derive(Debug, PartialEq, Eq)]
enum AlphaFault {
    /// The provider holds no source at that path.
    Absent,
    /// The walk stopped, and this is everything it had reached.
    Incomplete(AlphaFacts),
}

/// Why a beta request states no record. A different type from [`AlphaFault`],
/// carrying a different language's inventory, so the two answers cannot be
/// confused for one shared cause.
#[derive(Debug, PartialEq, Eq)]
enum BetaFault {
    /// The provider holds no source at that path.
    Absent,
    /// The walk stopped, and this is everything it had reached.
    Incomplete(BetaFacts),
}

/// One store that answers for both fact types, the way a repository store
/// answers for every language it admits.
#[derive(Default)]
struct TwoLanguageStore {
    requests: Vec<Box<str>>,
}

impl SourceProvider<AlphaFacts> for TwoLanguageStore {
    type Error = AlphaFault;

    fn source(&mut self, path: SourcePath<'_>) -> Result<SourceRecord<AlphaFacts>, Self::Error> {
        self.requests.push(Box::from(path.as_str()));
        match path.as_str() {
            "src/alpha.rs" => Ok(SourceRecord::new(
                Arc::from("fn alpha() {}\n"),
                [1_u8; 32],
                Arc::new(AlphaFacts { declarations: 1 }),
            )),
            "src/truncated.rs" => Err(AlphaFault::Incomplete(AlphaFacts { declarations: 0 })),
            _ => Err(AlphaFault::Absent),
        }
    }
}

impl SourceProvider<BetaFacts> for TwoLanguageStore {
    type Error = BetaFault;

    fn source(&mut self, path: SourcePath<'_>) -> Result<SourceRecord<BetaFacts>, Self::Error> {
        self.requests.push(Box::from(path.as_str()));
        match path.as_str() {
            "src/beta.go" => Ok(SourceRecord::new(
                Arc::from("package beta\n"),
                [2_u8; 32],
                Arc::new(BetaFacts { imports: 0 }),
            )),
            "src/truncated.go" => Err(BetaFault::Incomplete(BetaFacts { imports: 3 })),
            _ => Err(BetaFault::Absent),
        }
    }
}

/// A loader written against the contract alone: it names neither store nor
/// language, only the fact type it consumes and the error it maps.
fn declarations_of<P>(provider: &mut P, path: &str) -> Result<u32, P::Error>
where
    P: SourceProvider<AlphaFacts>,
{
    let request = SourcePath::new(path).expect("the fixture path is normalized");
    Ok(provider.source(request)?.facts().declarations)
}

/// The contract is generic over the fact type, states no root, refuses every
/// unnormalized request path, and shares one record rather than copying it.
#[test]
fn source_provider_contract_is_generic_root_neutral_and_closed() {
    normalized_paths_are_the_only_requests();
    one_store_answers_two_languages_with_two_typed_errors();
    a_record_shares_its_source_and_facts();
    this_crate_names_no_consumer();
}

/// Only an already-normalized repository-relative path is a request.
fn normalized_paths_are_the_only_requests() {
    for accepted in [
        "src/lib.rs",
        "a",
        "crates/pedant-core/src/resolution/mod.rs",
        "src/..lead.rs",
        "src/dotted.name.go",
        "src/a:b.rs",
    ] {
        let path = SourcePath::new(accepted)
            .unwrap_or_else(|| panic!("{accepted} is a normalized repository-relative path"));
        assert_eq!(path.as_str(), accepted, "the text is retained verbatim");
        assert_eq!(
            path.to_string(),
            accepted,
            "a request renders as the path it names"
        );
    }

    for refused in [
        "",
        "/etc/passwd",
        "../outside.rs",
        "src/../../outside.rs",
        "./src/lib.rs",
        "src/.",
        "src//lib.rs",
        "src/lib.rs/",
        "src\\lib.rs",
        "..",
        "C:/x",
        "C:\\x",
        "C:relative",
        "c:/x",
    ] {
        assert!(
            SourcePath::new(refused).is_none(),
            "{refused:?} is not a normalized repository-relative path"
        );
    }
}

/// One implementor answers for two unrelated fact types, and each answer
/// carries that language's own typed error rather than a shared cause.
fn one_store_answers_two_languages_with_two_typed_errors() {
    let mut store = TwoLanguageStore::default();

    assert_eq!(
        declarations_of(&mut store, "src/alpha.rs"),
        Ok(1),
        "the generic loader reads the alpha inventory through the contract alone"
    );
    assert_eq!(
        declarations_of(&mut store, "src/missing.rs"),
        Err(AlphaFault::Absent),
        "an alpha refusal is an alpha fault"
    );
    assert_eq!(
        declarations_of(&mut store, "src/truncated.rs"),
        Err(AlphaFault::Incomplete(AlphaFacts { declarations: 0 })),
        "an alpha fault carries the alpha inventory the walk had reached"
    );

    let beta = SourcePath::new("src/beta.go").expect("the fixture path is normalized");
    let record: SourceRecord<BetaFacts> = SourceProvider::<BetaFacts>::source(&mut store, beta)
        .expect("the store holds the beta source");
    assert_eq!(record.facts(), &BetaFacts { imports: 0 });
    assert_eq!(record.digest(), &[2_u8; 32]);

    let absent = SourcePath::new("src/missing.go").expect("the fixture path is normalized");
    assert_eq!(
        SourceProvider::<BetaFacts>::source(&mut store, absent).err(),
        Some(BetaFault::Absent),
        "a beta refusal is a beta fault"
    );
    let truncated = SourcePath::new("src/truncated.go").expect("the fixture path is normalized");
    assert_eq!(
        SourceProvider::<BetaFacts>::source(&mut store, truncated).err(),
        Some(BetaFault::Incomplete(BetaFacts { imports: 3 })),
        "a beta fault carries the beta inventory the walk had reached"
    );

    let requested: Box<[&str]> = store.requests.iter().map(|path| &**path).collect();
    assert_eq!(
        &*requested,
        [
            "src/alpha.rs",
            "src/missing.rs",
            "src/truncated.rs",
            "src/beta.go",
            "src/missing.go",
            "src/truncated.go"
        ],
        "every request reached the provider as its normalized path"
    );
}

/// A second holder of one record shares the one source and the one inventory.
fn a_record_shares_its_source_and_facts() {
    let mut store = TwoLanguageStore::default();
    let path = SourcePath::new("src/alpha.rs").expect("the fixture path is normalized");
    let record = SourceProvider::<AlphaFacts>::source(&mut store, path).expect("the alpha source");
    let second = record.clone();

    assert!(
        Arc::ptr_eq(&record.shared_text(), &second.shared_text()),
        "two holders share one source text"
    );
    assert!(
        Arc::ptr_eq(&record.shared_facts(), &second.shared_facts()),
        "two holders share one fact inventory"
    );
    assert_eq!(record.text(), "fn alpha() {}\n");
    assert_eq!(record.digest(), &[1_u8; 32]);
}

/// Every workspace member except this one.
///
/// Read out of the `members` array rather than restated, so a member added to
/// the workspace is a member this check already covers.
fn consumers() -> Box<[&'static str]> {
    let array = WORKSPACE
        .split_once("members = [")
        .expect("the workspace manifest states a members array")
        .1;
    let array = array
        .split_once(']')
        .expect("the members array is terminated")
        .0;
    array
        .split(',')
        .map(|member| member.trim().trim_matches('"'))
        .filter(|member| !member.is_empty() && *member != SELF_NAME)
        .collect()
}

/// Every dependency key the manifest states, from both the inline tables and
/// the `[dependencies.<name>]` headers.
///
/// A key, not a substring: `pedant-types` contains `pedant`, so a `contains`
/// test can never ask about the root crate at all.
fn dependency_keys(manifest: &str) -> Box<[&str]> {
    manifest
        .lines()
        .map(str::trim)
        .filter_map(|line| match line.strip_prefix('[') {
            Some(header) => header
                .strip_suffix(']')
                .and_then(|header| header.rsplit_once('.'))
                .filter(|(table, _)| table.ends_with("dependencies"))
                .map(|(_, name)| name),
            None => line
                .split_once('=')
                .map(|(key, _)| key.trim().trim_matches('"')),
        })
        .collect()
}

/// The contract sits beneath every consumer, so this crate names none of them.
fn this_crate_names_no_consumer() {
    let consumers = consumers();
    assert!(
        consumers.contains(&"pedant") && consumers.len() > 1,
        "the workspace members parsed as {consumers:?}, which names no root crate"
    );
    assert!(
        !consumers.contains(&SELF_NAME),
        "this crate is a member, not a consumer of itself"
    );

    let keys = dependency_keys(MANIFEST);
    for consumer in &consumers {
        assert!(
            !keys.contains(consumer),
            "pedant-types must not name {consumer}: the provider contract sits beneath it"
        );
    }
    assert!(
        MANIFEST.contains("name = \"pedant-types\""),
        "the manifest read is this crate's own"
    );
}
