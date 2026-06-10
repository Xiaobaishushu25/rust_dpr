use rustdpr_trace::{dpr_function, init_trace, install_panic_hook};
use zerocopy::{FromBytes, Immutable, KnownLayout, Ref, Unaligned};

#[repr(C)]
#[derive(Copy, Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
struct PacketHeader {
    tag: u8,
    flags: u8,
    len_le: [u8; 2],
}

pub fn run_input(data: &[u8]) -> usize {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    let _guard = dpr_function!("rw_zerocopy_header_ref::run_input");

    match Ref::<_, PacketHeader>::from_prefix(data) {
        Ok((header, body)) => {
            let header = *header;
            let declared = u16::from_le_bytes(header.len_le) as usize;
            declared.min(body.len()) ^ header.tag as usize ^ header.flags as usize
        }
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_header_view_do_not_panic() {
        let _ = run_input(&[1, 2, 3, 0, 9, 9, 9]);
    }
}
