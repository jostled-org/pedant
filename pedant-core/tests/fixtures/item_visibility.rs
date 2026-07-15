pub(super) struct DaemonState {
    counter: u32,
}

pub struct Widget;

pub(crate) enum Mode {
    On,
    Off,
}

pub(in crate::server) struct Scoped;

fn helper() {}

impl DaemonState {
    pub fn new() -> Self {
        Self { counter: 0 }
    }
}
