use rustdpr_trace::{dpr_function, init_trace, install_panic_hook};
use smallvec::SmallVec;

const MAX_OPS: usize = 512;

pub fn run_input(data: &[u8]) -> usize {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    let _guard = dpr_function!("rw_smallvec_ops::run_input");

    let mut vec: SmallVec<[u8; 8]> = SmallVec::new();
    for &byte in data.iter().take(MAX_OPS) {
        match byte % 6 {
            0 => vec.push(byte),
            1 => {
                if !vec.is_empty() {
                    let idx = (byte as usize) % vec.len();
                    vec.remove(idx);
                }
            }
            2 => {
                let idx = if vec.is_empty() { 0 } else { (byte as usize) % (vec.len() + 1) };
                vec.insert(idx, byte);
            }
            3 => vec.retain(|x| (*x ^ byte) & 1 == 0),
            4 => vec.sort_unstable(),
            _ => vec.truncate((byte as usize).min(vec.len())),
        }
        if vec.len() > MAX_OPS {
            vec.clear();
        }
    }

    vec.iter().fold(vec.len(), |acc, value| acc.wrapping_add(*value as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_ops_do_not_panic() {
        let _ = run_input(&[0, 1, 2, 3, 4, 5, 250, 251]);
    }
}
