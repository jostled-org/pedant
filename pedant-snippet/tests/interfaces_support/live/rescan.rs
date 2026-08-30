//! Typed watcher reports that require whole-tree resynchronization.

use notify::event::Flag;
use notify::{Event, EventKind};
use pedant_snippet::requires_rescan;

/// A dropped-event notice carries no path but still requests a rescan.
#[test]
fn dropped_event_notice_requests_rescan() {
    let event = Event::new(EventKind::Any).set_flag(Flag::Rescan);
    assert!(requires_rescan(Ok(event)));
}

/// A backend refusal cannot leave the live index silently current.
#[test]
fn backend_refusal_requests_rescan() {
    assert!(requires_rescan(Err(notify::Error::generic(
        "backend stopped"
    ))));
}

/// An ordinary pathless event asks for no work.
#[test]
fn ordinary_pathless_event_does_not_request_rescan() {
    assert!(!requires_rescan(Ok(Event::new(EventKind::Any))));
}
