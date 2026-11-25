#![no_main]
use libfuzzer_sys::fuzz_target;
use newos_net::parse_ipv4;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = parse_ipv4(s);
    }
});
