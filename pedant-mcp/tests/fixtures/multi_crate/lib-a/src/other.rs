use std::fs;

pub fn read_config() -> std::io::Result<String> {
    fs::read_to_string("config.toml")
}
