trait Handler {
    fn handle(&self);
}

fn takes_ref_dyn(h: &dyn Handler) {
    h.handle();
}

fn takes_box_dyn(h: Box<dyn Handler>) {
    h.handle();
}

fn takes_generic<H: Handler>(h: &H) {
    h.handle();
}
