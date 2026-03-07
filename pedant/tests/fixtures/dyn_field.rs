use std::sync::Arc;
use std::rc::Rc;

trait Transport {
    fn send(&self, data: &[u8]);
}

struct ClientBox {
    transport: Box<dyn Transport>,
}

struct ClientArc {
    transport: Arc<dyn Transport>,
}

struct ClientRc {
    transport: Rc<dyn Transport>,
}

struct ClientGeneric<T: Transport> {
    transport: T,
}
