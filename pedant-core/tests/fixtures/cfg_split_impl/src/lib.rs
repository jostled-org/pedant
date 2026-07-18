//! Legitimate platform split: the two impl files are mutually exclusive, so
//! their methods never coexist in a single build.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub struct Handle {
    pub fd: i32,
}

pub struct Direct {
    pub fd: i32,
}
