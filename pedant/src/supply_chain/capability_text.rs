use pedant_types::{Capability, CapabilityProfile};

pub(super) fn capability_list(profile: &CapabilityProfile) -> String {
    capability_names(&profile.capabilities())
}

pub(super) fn capability_names(capabilities: &[Capability]) -> String {
    match capabilities.is_empty() {
        true => String::from("none"),
        false => capabilities
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    }
}
