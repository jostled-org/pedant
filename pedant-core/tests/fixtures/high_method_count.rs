struct Helper;

struct Engine {
    inner: Helper,
}

// First inherent impl: three substantive methods plus two pure forwarders.
impl Engine {
    fn a(&self) -> u32 {
        1
    }
    fn b(&self) -> u32 {
        2
    }
    fn c(&self) -> u32 {
        let x = 3;
        x
    }
    fn fwd_a(&self) -> u32 {
        self.inner.value()
    }
    fn fwd_b(&self) -> Option<u32> {
        self.inner.compute()?
    }
}

// Second inherent impl: aggregate count must sum across both blocks.
impl Engine {
    fn d(&self) -> u32 {
        4
    }
    fn e(&self) -> u32 {
        5
    }
    fn f(&self) -> u32 {
        6
    }
}

// Trait impl methods are contract obligations, not the type's own surface.
impl Compute for Engine {
    fn compute(&self) -> u32 {
        self.a() + self.d()
    }
}

// A properly-decomposed facade: many forwarders, one real method.
struct Facade {
    inner: Helper,
}

impl Facade {
    fn one(&self) -> u32 {
        self.inner.one()
    }
    fn two(&self) -> u32 {
        self.inner.two()
    }
    fn three(&self) -> u32 {
        self.inner.three()
    }
    fn four(&self) -> u32 {
        self.inner.four()
    }
    fn five(&self) -> u32 {
        self.inner.five()
    }
    fn six(&self) -> u32 {
        self.inner.six()
    }
    fn seven(&self) -> u32 {
        self.inner.seven()
    }
    fn eight(&self) -> u32 {
        self.inner.eight()
    }
    fn real(&self) -> u32 {
        let total = self.inner.one() + 1;
        total
    }
}
