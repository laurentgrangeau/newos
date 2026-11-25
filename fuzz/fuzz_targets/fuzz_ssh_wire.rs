#![no_main]
use libfuzzer_sys::fuzz_target;
use newos_ssh_proto::wire::WireReader;

fuzz_target!(|data: &[u8]| {
    let mut r = WireReader::new(data);
    let _ = r.read_u8();
    let _ = r.read_bool();
    let _ = r.read_u32();
    let _ = r.read_string();
    let _ = r.read_str();
});
