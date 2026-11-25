#![no_main]
use libfuzzer_sys::fuzz_target;
use xtask::profile::BuildProfile;

fuzz_target!(|data: &[u8]| {
    let _ = xtask::gpt::crc32(data);
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = BuildProfile::parse_toml(s);
    }
});
