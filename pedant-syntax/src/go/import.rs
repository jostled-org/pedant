//! The imports one Go file states, and the names each binds.

use crate::go::context::{field_text, text};
use crate::go::span::GoFactSpan;
use crate::tree_sitter::Node;

/// The form one import specification is written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoImportForm {
    /// `import "net/http"`, which binds the package's own declared name.
    Named,
    /// `import alias "net/http"`, which binds the stated alias.
    Aliased,
    /// `import . "strings"`, which binds every exported name of the package
    /// into file scope.
    Dot,
    /// `import _ "embed"`, which binds no name.
    Blank,
}

/// One import specification, exactly as its file writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoImportFact<'source> {
    form: GoImportForm,
    path: &'source str,
    alias: Option<&'source str>,
    local_name: Option<&'source str>,
    span: GoFactSpan,
}

impl<'source> GoImportFact<'source> {
    /// The form the specification is written in.
    pub fn form(&self) -> GoImportForm {
        self.form
    }

    /// The import path, without its quotes.
    pub fn path(&self) -> &'source str {
        self.path
    }

    /// The explicit alias, present only for [`GoImportForm::Aliased`].
    pub fn alias(&self) -> Option<&'source str> {
        self.alias
    }

    /// The name this file binds for the package.
    ///
    /// The explicit alias when the file states one, and the import path's last
    /// segment otherwise. That last segment is what the file assumes, not what
    /// the imported package declares; a resolver holding the imported package
    /// reads the declared name and may disagree. A dot or blank import binds no
    /// single name and answers `None`.
    pub fn local_name(&self) -> Option<&'source str> {
        self.local_name
    }

    /// The extent of the specification.
    pub fn span(&self) -> GoFactSpan {
        self.span
    }
}

/// The import `node` states, if it states one.
pub(super) fn import_at<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<GoImportFact<'source>> {
    if node.kind() != "import_spec" {
        return None;
    }
    let path = unquote(field_text(node, "path", source)?);
    let (form, alias) = form_of(node, source);
    Some(GoImportFact {
        form,
        path,
        alias,
        local_name: bound_name(form, alias, path),
        span: GoFactSpan::of_node(node),
    })
}

/// The form and explicit alias one specification's `name` child states.
fn form_of<'source>(node: Node<'_>, source: &'source str) -> (GoImportForm, Option<&'source str>) {
    let Some(name) = node.child_by_field_name("name") else {
        return (GoImportForm::Named, None);
    };
    match name.kind() {
        "dot" => (GoImportForm::Dot, None),
        "blank_identifier" => (GoImportForm::Blank, None),
        _ => (GoImportForm::Aliased, Some(text(name, source))),
    }
}

/// The name a form binds in file scope.
fn bound_name<'source>(
    form: GoImportForm,
    alias: Option<&'source str>,
    path: &'source str,
) -> Option<&'source str> {
    match form {
        GoImportForm::Aliased => alias,
        GoImportForm::Named => Some(path.rsplit('/').next().unwrap_or(path)),
        GoImportForm::Dot | GoImportForm::Blank => None,
    }
}

/// One import path literal with its delimiters removed.
///
/// Go writes an import path as an interpreted string or a raw string, and both
/// delimiters are single bytes, so the path is a slice of the source rather
/// than a rebuilt string. An interpreted path carrying an escape would not
/// name an importable directory, so nothing is unescaped here.
fn unquote(literal: &str) -> &str {
    literal
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .or_else(|| {
            literal
                .strip_prefix('`')
                .and_then(|rest| rest.strip_suffix('`'))
        })
        .unwrap_or(literal)
}
