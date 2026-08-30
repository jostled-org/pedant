//! The transport journeys: the spawned CLI, the real stdio server, and the
//! cutover that left exactly these two.
//!
//! Every module here reads the same mixed six-language repository the index
//! cases build, so all of them sit behind the shared complete-profile gate: a
//! claim about a Go relation beside a TypeScript outline is unanswerable by a
//! build that links one of them.

use crate::profile_gate::complete_profile_modules;

complete_profile_modules!(
    cli_graph,
    cli_inventory,
    cli_navigation,
    client,
    envelopes,
    fixture,
    legacy,
    mcp_live,
    mcp_registry,
    mcp_shutdown,
    outcome,
    parity,
    platform,
);
