//! Shape A: `extra` is a DEFAULT feature, so `extra.rs` compiles in every
//! ordinary build. The gate must not buy an exemption.

#[cfg(feature = "extra")]
mod extra;

pub struct God {
    pub n: usize,
}

impl God {
    pub fn a0(&self) -> usize { self.n + 0 }
    pub fn a1(&self) -> usize { self.n + 1 }
    pub fn a2(&self) -> usize { self.n + 2 }
    pub fn a3(&self) -> usize { self.n + 3 }
    pub fn a4(&self) -> usize { self.n + 4 }
    pub fn a5(&self) -> usize { self.n + 5 }
    pub fn a6(&self) -> usize { self.n + 6 }
    pub fn a7(&self) -> usize { self.n + 7 }
}
