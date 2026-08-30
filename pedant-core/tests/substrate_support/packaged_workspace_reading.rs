//! The one reading of the tracked packaged-workspace release proof its provers
//! share.
//!
//! Split out of [`crate::packaged_workspace_claims`], which owns the tables that
//! reading is compared against. A table is a stated constant; a reading is
//! filesystem state a process holds once. Keeping both in one module left two
//! type groups with nothing between them, and pedant's `mixed-concerns` rule
//! refused it.
//!
//! Every prover names this module directly rather than reaching the reader
//! through the claims module. A re-export would be a second path to one name,
//! which is the thing a single owner is for — the same rule
//! [`crate::shell_script_reading`] states for the readers it owns.
//!
//! How a tracked file is read at all is neither module's: that is
//! [`crate::resolution::authority_scan::read_text`], which every structural claim
//! in this repository shares.

use std::sync::OnceLock;

use crate::resolution::authority_scan::read_text;
use crate::shell_script_reading::joined_lines;

/// The tracked proof that compiles the release archives as a registry consumer
/// receives them.
pub(crate) const PACKAGED_WORKSPACE_SCRIPT: &str = ".github/scripts/check_packaged_workspace.sh";

/// That script in the two spellings its provers read it in.
pub(crate) struct ProofScript {
    /// The script exactly as tracked, for a claim about what one function body
    /// holds line by line.
    pub(crate) source: &'static str,
    /// The same script with every continued line folded onto one, for a claim
    /// about a whole command.
    pub(crate) joined: &'static str,
}

/// The tracked proof, read and joined once for the process.
///
/// Three predicates read it — the structural contract, the journey
/// registration, and the release contract — and each paid for its own read of
/// the same script, two of them for its own line joining as well. The answer is
/// a property of the commit, so one reading serves all three, the way one
/// parsed manifest serves every claim made about a manifest.
///
/// Both spellings come from that one reading. A reader that returned only the
/// raw text would leave the join to be rebuilt beside it, which is the second
/// copy this exists to remove.
pub(crate) fn packaged_workspace_script() -> &'static ProofScript {
    static SCRIPT: OnceLock<ProofScript> = OnceLock::new();
    SCRIPT.get_or_init(|| {
        let source: &'static str = Box::leak(read_text(PACKAGED_WORKSPACE_SCRIPT).into_boxed_str());
        ProofScript {
            source,
            joined: Box::leak(joined_lines(source)),
        }
    })
}
