//! This crate defines a set of traits which describe the functionality of
//! [block ciphers][1] and [stream ciphers][2].
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher
//! [2]: https://en.wikipedia.org/wiki/Stream_cipher

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "dev")]
pub use blobby;

mod block;
#[cfg(feature = "dev")]
mod dev;
pub mod errors;
mod stream;

pub use crate::{block::*, stream::*};
pub use crypto_common::{FromKey, FromKeyNonce};
pub use generic_array::{self, typenum::consts};
