fn loop_clone(items: &[String]) {
    for item in items {
        let owned = item.clone();
        drop(owned);
    }
}

fn while_clone(items: &[String]) {
    let mut i = 0;
    while i < items.len() {
        let owned = items[i].clone();
        drop(owned);
        i += 1;
    }
}

fn plain_loop_clone(s: &str) {
    loop {
        let owned = s.to_string();
        let cloned = owned.clone();
        drop(cloned);
        break;
    }
}

fn no_loop_clone(s: &String) -> String {
    s.clone()
}

use std::sync::Arc;
use std::rc::Rc;

// Clean: Arc param cloned in loop is O(1) refcount bump
fn arc_param_clone(data: Arc<str>) {
    for _ in 0..10 {
        let cloned = data.clone();
        drop(cloned);
    }
}

// Clean: Rc param cloned in loop is O(1) refcount bump
fn rc_param_clone(data: Rc<String>) {
    for _ in 0..10 {
        let cloned = data.clone();
        drop(cloned);
    }
}

// Clean: typed let binding with Arc
fn arc_let_clone() {
    let data: Arc<str> = Arc::from("hello");
    for _ in 0..10 {
        let cloned = data.clone();
        drop(cloned);
    }
}

// Clean: param contains Arc in generic args, loop bindings inferred refcounted
fn arc_iter_clone(items: &[Arc<str>]) {
    for item in items {
        let cloned = item.clone();
        drop(cloned);
    }
}

// Clean: destructuring a container with Arc type args
fn arc_destructure_clone(pairs: &[(Arc<str>, Arc<str>)]) {
    for (key, value) in pairs {
        let k = key.clone();
        let v = value.clone();
        drop(k);
        drop(v);
    }
}

// Still flagged: inferred type, no Arc/Rc in param
fn inferred_clone_in_loop(items: &[String]) {
    for item in items {
        let owned = item.clone();
        drop(owned);
    }
}
