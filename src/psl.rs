//! Embedded Public Suffix List loader.
//!
//! The PSL is vendored at build time via `include_str!` so the binary has no
//! runtime dependency on network access or the filesystem. The compiled
//! `publicsuffix::List` is shared via `OnceLock`.

use once_cell::sync::Lazy;
use publicsuffix::List;

const PSL_RAW: &str = include_str!("../assets/public_suffix_list.dat");

pub static LIST: Lazy<List> = Lazy::new(|| {
    PSL_RAW
        .parse()
        .expect("vendored public_suffix_list.dat must parse")
});
