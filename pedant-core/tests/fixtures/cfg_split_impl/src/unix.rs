use super::{Direct, Handle};

// Reached only through `#[cfg(unix)] mod unix;` in lib.rs.
impl Handle {
    pub fn u0(&self) -> i32 {
        self.fd + 0
    }
    pub fn u1(&self) -> i32 {
        self.fd + 1
    }
    pub fn u2(&self) -> i32 {
        self.fd + 2
    }
    pub fn u3(&self) -> i32 {
        self.fd + 3
    }
    pub fn u4(&self) -> i32 {
        self.fd + 4
    }
    pub fn u5(&self) -> i32 {
        self.fd + 5
    }
    pub fn u6(&self) -> i32 {
        self.fd + 6
    }
    pub fn u7(&self) -> i32 {
        self.fd + 7
    }
    pub fn u8(&self) -> i32 {
        self.fd + 8
    }
    pub fn u9(&self) -> i32 {
        self.fd + 9
    }
}

// Gated on the impl block itself rather than the module declaration.
#[cfg(unix)]
impl Direct {
    pub fn u0(&self) -> i32 {
        self.fd + 0
    }
    pub fn u1(&self) -> i32 {
        self.fd + 1
    }
    pub fn u2(&self) -> i32 {
        self.fd + 2
    }
    pub fn u3(&self) -> i32 {
        self.fd + 3
    }
    pub fn u4(&self) -> i32 {
        self.fd + 4
    }
    pub fn u5(&self) -> i32 {
        self.fd + 5
    }
    pub fn u6(&self) -> i32 {
        self.fd + 6
    }
    pub fn u7(&self) -> i32 {
        self.fd + 7
    }
    pub fn u8(&self) -> i32 {
        self.fd + 8
    }
    pub fn u9(&self) -> i32 {
        self.fd + 9
    }
}
