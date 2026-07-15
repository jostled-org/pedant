//! A module root should only wire the tree together and re-export.

pub mod helpers;
pub use helpers::Thing;

pub struct Local;

pub enum Kind {
    A,
    B,
}

pub union Bytes {
    a: u32,
    b: f32,
}

pub trait Doer {
    fn do_it(&self);
}

impl Doer for Local {
    fn do_it(&self) {}
}

pub fn helper() {}
