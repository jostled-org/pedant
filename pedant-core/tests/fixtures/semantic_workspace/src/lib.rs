use std::sync::Arc;
use std::collections::HashMap;

/// Type alias for Arc<String> — tests alias resolution.
pub type MyArc = Arc<String>;

/// Type alias for HashMap — tests default hasher detection through alias.
pub type MyHashMap = HashMap<String, i32>;

/// Function returning a type alias — tests resolve_type at return position.
pub fn foo() -> MyArc {
    todo!()
}

/// Function returning a HashMap alias.
pub fn bar() -> MyHashMap {
    todo!()
}

/// A comment line for testing unknown position.
// This is a plain comment.

/// Type alias for Arc<String> used in binding tests.
pub type Handle = Arc<String>;

/// Function with a binding typed via alias — tests extract enrichment.
#[allow(unused)]
pub fn binding_through_alias() {
    let h: Handle = Arc::new(String::new());
}

/// Function with a clone in a loop on an aliased Arc receiver.
/// Without semantic analysis, `Handle` is not recognized as Arc.
pub fn clone_aliased_arc_in_loop() {
    let h: Handle = Arc::new(String::new());
    loop {
        let _ = h.clone();
    }
}

/// Function with a clone in a loop on a String receiver.
pub fn clone_string_in_loop() {
    let s: String = String::new();
    loop {
        let _ = s.clone();
    }
}

/// Function with a clone in a loop on a Copy type.
pub fn clone_copy_in_loop() {
    let n: i32 = 0;
    loop {
        let _ = n.clone();
    }
}
