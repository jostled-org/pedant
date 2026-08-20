//! One `go.mod` read from inside the repository root, interpreted into the
//! declarations a project admits.
//!
//! Interpretation stops at what the file says. Precedence between declarations,
//! and the decision to follow any of them, belong to the loader.

use std::path::Path;
use std::sync::Arc;

use super::directive::{ARROW, GoDirective};
use super::error::GoProjectError;
use super::replacement::GoReplacementTarget;
use super::{directive, paths};
use crate::observe::{self, Observation};

/// One `require` declaration, exactly as written.
pub(super) struct ParsedRequirement {
    pub(super) path: Box<str>,
    pub(super) version: Box<str>,
}

/// One `exclude` declaration, exactly as written.
pub(super) struct ParsedExclusion {
    pub(super) path: Box<str>,
    pub(super) version: Box<str>,
}

/// One `replace` declaration, exactly as written.
pub(super) struct ParsedReplacement {
    pub(super) path: Box<str>,
    pub(super) version: Option<Box<str>>,
    pub(super) target: GoReplacementTarget,
}

/// One interpreted manifest: its identity, its module path, and its
/// declarations in deterministic order.
pub(super) struct GoManifestDocument {
    pub(super) relative: Box<str>,
    pub(super) module: Arc<str>,
    pub(super) requirements: Box<[ParsedRequirement]>,
    pub(super) exclusions: Box<[ParsedExclusion]>,
    pub(super) replacements: Box<[ParsedReplacement]>,
    pub(super) digest: [u8; 32],
}

/// The declarations one manifest states, before they are ordered and checked.
#[derive(Default)]
struct ManifestDraft {
    module: Option<Arc<str>>,
    requirements: Vec<ParsedRequirement>,
    exclusions: Vec<ParsedExclusion>,
    replacements: Vec<ParsedReplacement>,
}

/// Directives the `go.mod` grammar defines that state nothing a project model
/// reads. They are recognized so an unknown verb stays an error.
const IGNORED_VERBS: &[&str] = &["go", "toolchain", "godebug", "retract", "tool", "ignore"];

impl GoManifestDocument {
    /// Read and interpret one manifest that lies inside `root`.
    ///
    /// Normalization comes first: it is pure path arithmetic, and it refuses a
    /// path the root does not contain before the read rather than after it. The
    /// observation follows the read, because an absent manifest is how the
    /// loader learns a replacement target has none — that is not a read, and it
    /// must not be recorded as one.
    pub(super) fn read(root: &Path, path: &Path) -> Result<Self, GoProjectError> {
        let relative = paths::relative_text(root, path)?;
        let text =
            std::fs::read_to_string(path).map_err(|source| GoProjectError::ManifestRead {
                path: paths::path_text(path),
                source,
            })?;
        observe::record(Observation::ManifestRead(&relative));
        interpret(relative, &text)
    }
}

/// Turn one manifest's text into its ordered, checked declarations.
fn interpret(relative: Box<str>, text: &str) -> Result<GoManifestDocument, GoProjectError> {
    let directives = directive::parse(text).map_err(|error| GoProjectError::ManifestParse {
        path: relative.clone(),
        line: error.line,
        message: error.message,
    })?;
    let mut draft = ManifestDraft::default();
    for entry in directives.iter() {
        apply(&mut draft, entry, &relative)?;
    }
    seal(relative, draft, text)
}

/// Apply one directive to the draft.
fn apply(
    draft: &mut ManifestDraft,
    entry: &GoDirective,
    manifest: &str,
) -> Result<(), GoProjectError> {
    match &*entry.verb {
        "module" => set_module(draft, entry, manifest),
        "require" => {
            draft.requirements.push(parse_requirement(entry, manifest)?);
            Ok(())
        }
        "exclude" => {
            draft.exclusions.push(parse_exclusion(entry, manifest)?);
            Ok(())
        }
        "replace" => {
            draft.replacements.push(parse_replacement(entry, manifest)?);
            Ok(())
        }
        verb if IGNORED_VERBS.contains(&verb) => Ok(()),
        verb => Err(malformed(
            manifest,
            entry.line,
            format!("unknown directive {verb}"),
        )),
    }
}

/// Record the one module path a manifest may declare.
fn set_module(
    draft: &mut ManifestDraft,
    entry: &GoDirective,
    manifest: &str,
) -> Result<(), GoProjectError> {
    let [declared] = &*entry.arguments else {
        return Err(malformed(
            manifest,
            entry.line,
            "a module directive names one module path".to_owned(),
        ));
    };
    match draft.module.replace(Arc::from(&**declared)) {
        None => Ok(()),
        Some(_) => Err(malformed(
            manifest,
            entry.line,
            "the module path is declared more than once".to_owned(),
        )),
    }
}

/// Order the draft's declarations, refuse duplicate keys, and seal the document.
fn seal(
    relative: Box<str>,
    draft: ManifestDraft,
    text: &str,
) -> Result<GoManifestDocument, GoProjectError> {
    let module = draft
        .module
        .ok_or_else(|| GoProjectError::MissingModuleDeclaration {
            path: relative.clone(),
        })?;
    let mut requirements = draft.requirements;
    let mut exclusions = draft.exclusions;
    let mut replacements = draft.replacements;
    requirements
        .sort_by(|left, right| (&left.path, &left.version).cmp(&(&right.path, &right.version)));
    exclusions
        .sort_by(|left, right| (&left.path, &left.version).cmp(&(&right.path, &right.version)));
    replacements
        .sort_by(|left, right| (&left.path, &left.version).cmp(&(&right.path, &right.version)));
    check_unique_requirements(&relative, &requirements)?;
    check_unique_exclusions(&relative, &exclusions)?;
    check_unique_replacements(&relative, &replacements)?;
    Ok(GoManifestDocument {
        relative,
        module,
        requirements: requirements.into_boxed_slice(),
        exclusions: exclusions.into_boxed_slice(),
        replacements: replacements.into_boxed_slice(),
        digest: crate::hash::digest_bytes(text.as_bytes()),
    })
}

/// A module path may be required at most once in one manifest.
fn check_unique_requirements(
    manifest: &str,
    requirements: &[ParsedRequirement],
) -> Result<(), GoProjectError> {
    let repeated = requirements
        .windows(2)
        .find(|pair| pair[0].path == pair[1].path);
    match repeated {
        None => Ok(()),
        Some(pair) => Err(GoProjectError::DuplicateRequirement {
            path: manifest.into(),
            module: pair[0].path.clone(),
        }),
    }
}

/// An exact module version may be excluded at most once in one manifest.
fn check_unique_exclusions(
    manifest: &str,
    exclusions: &[ParsedExclusion],
) -> Result<(), GoProjectError> {
    let repeated = exclusions
        .windows(2)
        .find(|pair| pair[0].path == pair[1].path && pair[0].version == pair[1].version);
    match repeated {
        None => Ok(()),
        Some(pair) => Err(GoProjectError::DuplicateExclusion {
            path: manifest.into(),
            module: pair[0].path.clone(),
            version: pair[0].version.clone(),
        }),
    }
}

/// A replacement key — old path plus optional old version — may appear at most
/// once in one manifest, because that key is what precedence selects on.
fn check_unique_replacements(
    manifest: &str,
    replacements: &[ParsedReplacement],
) -> Result<(), GoProjectError> {
    let repeated = replacements
        .windows(2)
        .find(|pair| pair[0].path == pair[1].path && pair[0].version == pair[1].version);
    match repeated {
        None => Ok(()),
        Some(pair) => Err(GoProjectError::DuplicateReplacement {
            path: manifest.into(),
            module: pair[0].path.clone(),
            version: version_key(pair[0].version.as_deref()),
        }),
    }
}

/// How a replacement key's optional version reads in a refusal.
fn version_key(version: Option<&str>) -> Box<str> {
    match version {
        Some(version) => version.into(),
        None => Box::from("any version"),
    }
}

fn parse_requirement(
    entry: &GoDirective,
    manifest: &str,
) -> Result<ParsedRequirement, GoProjectError> {
    let [path, version] = &*entry.arguments else {
        return Err(malformed(
            manifest,
            entry.line,
            "a requirement names one module path and one version".to_owned(),
        ));
    };
    Ok(ParsedRequirement {
        path: path.clone(),
        version: checked_version(manifest, (path, version))?,
    })
}

fn parse_exclusion(entry: &GoDirective, manifest: &str) -> Result<ParsedExclusion, GoProjectError> {
    let [path, version] = &*entry.arguments else {
        return Err(malformed(
            manifest,
            entry.line,
            "an exclusion names one module path and one version".to_owned(),
        ));
    };
    Ok(ParsedExclusion {
        path: path.clone(),
        version: checked_version(manifest, (path, version))?,
    })
}

fn parse_replacement(
    entry: &GoDirective,
    manifest: &str,
) -> Result<ParsedReplacement, GoProjectError> {
    let arrow = entry
        .arguments
        .iter()
        .position(|token| &**token == ARROW)
        .ok_or_else(|| {
            malformed(
                manifest,
                entry.line,
                format!("a replacement separates its sides with {ARROW}"),
            )
        })?;
    let (old, arrowed) = entry.arguments.split_at(arrow);
    let new = arrowed.split_first().map(|(_, rest)| rest).unwrap_or(&[]);
    let (path, version) = parse_replaced(old, (manifest, entry.line))?;
    Ok(ParsedReplacement {
        path,
        version,
        target: parse_target(new, (manifest, entry.line))?,
    })
}

/// The old side of a replacement: a module path, and optionally the one version
/// the entry applies to.
fn parse_replaced(
    old: &[Box<str>],
    context: (&str, u32),
) -> Result<(Box<str>, Option<Box<str>>), GoProjectError> {
    let (manifest, line) = context;
    match old {
        [path] => Ok((path.clone(), None)),
        [path, version] => Ok((
            path.clone(),
            Some(checked_version(manifest, (path, version))?),
        )),
        _ => Err(malformed(
            manifest,
            line,
            "a replacement replaces one module path".to_owned(),
        )),
    }
}

/// The new side of a replacement: a directory, or another module version.
fn parse_target(
    new: &[Box<str>],
    context: (&str, u32),
) -> Result<GoReplacementTarget, GoProjectError> {
    let (manifest, line) = context;
    match new {
        [target] if is_directory_target(target) => Ok(GoReplacementTarget::LocalDirectory(
            normalize_target(target),
        )),
        [_] => Err(malformed(
            manifest,
            line,
            "a replacement without a version must name a directory path".to_owned(),
        )),
        [target, _] if is_directory_target(target) => Err(malformed(
            manifest,
            line,
            "a directory replacement takes no version".to_owned(),
        )),
        [target, version] => Ok(GoReplacementTarget::Module {
            path: Arc::from(&**target),
            version: Arc::from(&*checked_version(manifest, (target, version))?),
        }),
        _ => Err(malformed(
            manifest,
            line,
            "a replacement names one target".to_owned(),
        )),
    }
}

/// Go admits a filesystem replacement target only when it is rooted or starts
/// with `./` or `../`, which is what tells a directory from a module path.
fn is_directory_target(target: &str) -> bool {
    target.starts_with("./") || target.starts_with("../") || Path::new(target).is_absolute()
}

/// The target as the loader states it: `/`-separated, without a `./` prefix.
fn normalize_target(target: &str) -> Box<str> {
    target.strip_prefix("./").unwrap_or(target).into()
}

/// One declared version, or the refusal it earns.
fn checked_version(manifest: &str, declaration: (&str, &str)) -> Result<Box<str>, GoProjectError> {
    let (module, version) = declaration;
    match is_module_version(version) {
        true => Ok(version.into()),
        false => Err(GoProjectError::InvalidVersion {
            path: manifest.into(),
            module: module.into(),
            version: version.into(),
        }),
    }
}

/// Whether `version` is a `v`-prefixed semantic version, which is the only form
/// a `go.mod` states.
fn is_module_version(version: &str) -> bool {
    version
        .strip_prefix('v')
        .is_some_and(|core| semver::Version::parse(core).is_ok())
}

fn malformed(manifest: &str, line: u32, message: String) -> GoProjectError {
    GoProjectError::ManifestParse {
        path: manifest.into(),
        line,
        message: message.into_boxed_str(),
    }
}
