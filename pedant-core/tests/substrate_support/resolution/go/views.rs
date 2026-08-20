//! Flat renderings of a loaded Go project.
//!
//! Every case compares whole ordered lists of these strings rather than probing
//! one field at a time, so a record that gained, lost, or reordered a claim
//! fails the comparison instead of slipping past an assertion that never asked.

use pedant_core::resolution::go::{
    GoProject, GoReplacement, GoReplacementTarget, GoRequirement, GoRequirementResolution,
};

/// Borrow a rendered list so it compares against a written-down `&str` table.
pub fn borrowed(list: &[Box<str>]) -> Box<[&str]> {
    list.iter().map(|line| &**line).collect()
}

/// `<module path>|<directory>|<manifest>|<depth>` for every admitted module.
pub fn modules(project: &GoProject) -> Box<[Box<str>]> {
    project
        .modules()
        .map(|module| {
            format!(
                "{}|{}|{}|{}",
                module.path(),
                module.directory(),
                module.manifest(),
                module.depth()
            )
            .into_boxed_str()
        })
        .collect()
}

/// `<declaring module>|<required path>|<required version>|<resolution>` for
/// every requirement, in project order.
pub fn requirements(project: &GoProject) -> Box<[Box<str>]> {
    project
        .requirements()
        .iter()
        .map(|requirement| requirement_text(project, requirement))
        .collect()
}

fn requirement_text(project: &GoProject, requirement: &GoRequirement) -> Box<str> {
    let declaring = project
        .module(requirement.module())
        .expect("a requirement names a module of its own project");
    format!(
        "{}|{}|{}|{}",
        declaring.path(),
        requirement.path(),
        requirement.version(),
        resolution_text(project, requirement.resolution())
    )
    .into_boxed_str()
}

fn resolution_text(project: &GoProject, resolution: &GoRequirementResolution) -> Box<str> {
    match resolution {
        GoRequirementResolution::External => Box::from("external"),
        GoRequirementResolution::ReplacedModule { path, version } => {
            format!("module:{path}@{version}").into_boxed_str()
        }
        GoRequirementResolution::LocalModule(id) => {
            let module = project
                .module(*id)
                .expect("a local resolution names a module of its own project");
            format!("local:{}", module.path()).into_boxed_str()
        }
    }
}

/// `<old path>|<old version>|<target>|<applied>` for every root replacement.
pub fn replacements(project: &GoProject) -> Box<[Box<str>]> {
    project
        .replacements()
        .iter()
        .map(|replacement| {
            format!(
                "{}|{}|{}|{}",
                replacement.path(),
                replacement.version().unwrap_or("*"),
                target_text(replacement),
                replacement.is_applied()
            )
            .into_boxed_str()
        })
        .collect()
}

fn target_text(replacement: &GoReplacement) -> Box<str> {
    match replacement.target() {
        GoReplacementTarget::LocalDirectory(directory) => {
            format!("dir:{directory}").into_boxed_str()
        }
        GoReplacementTarget::Module { path, version } => {
            format!("module:{path}@{version}").into_boxed_str()
        }
    }
}

/// `<path>|<version>` for every root exclusion.
pub fn exclusions(project: &GoProject) -> Box<[Box<str>]> {
    project
        .exclusions()
        .iter()
        .map(|exclusion| format!("{}|{}", exclusion.path(), exclusion.version()).into_boxed_str())
        .collect()
}
