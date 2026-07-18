use super::{Direct, Handle};

// Reached only through `#[cfg(windows)] mod windows;` in lib.rs.
impl Handle {
    pub fn w0(&self) -> i32 {
        self.fd + 0
    }
    pub fn w1(&self) -> i32 {
        self.fd + 1
    }
    pub fn w2(&self) -> i32 {
        self.fd + 2
    }
    pub fn w3(&self) -> i32 {
        self.fd + 3
    }
    pub fn w4(&self) -> i32 {
        self.fd + 4
    }
    pub fn w5(&self) -> i32 {
        self.fd + 5
    }
    pub fn w6(&self) -> i32 {
        self.fd + 6
    }
    pub fn w7(&self) -> i32 {
        self.fd + 7
    }
    pub fn w8(&self) -> i32 {
        self.fd + 8
    }
    pub fn w9(&self) -> i32 {
        self.fd + 9
    }
}

// Gated on the impl block itself rather than the module declaration.
#[cfg(windows)]
impl Direct {
    pub fn w0(&self) -> i32 {
        self.fd + 0
    }
    pub fn w1(&self) -> i32 {
        self.fd + 1
    }
    pub fn w2(&self) -> i32 {
        self.fd + 2
    }
    pub fn w3(&self) -> i32 {
        self.fd + 3
    }
    pub fn w4(&self) -> i32 {
        self.fd + 4
    }
    pub fn w5(&self) -> i32 {
        self.fd + 5
    }
    pub fn w6(&self) -> i32 {
        self.fd + 6
    }
    pub fn w7(&self) -> i32 {
        self.fd + 7
    }
    pub fn w8(&self) -> i32 {
        self.fd + 8
    }
    pub fn w9(&self) -> i32 {
        self.fd + 9
    }
}
