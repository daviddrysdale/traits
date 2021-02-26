//! Non-streaming block cipher .
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

use block_buffer::{BlockBuffer, block_padding::Padding};
use crate::{BlockMode, BlockCipher, FromBlockCipherNonce};
use crate::errors::InvalidLength;
use generic_array::{GenericArray, typenum::Unsigned};
use core::{slice::from_mut, marker::PhantomData};

pub struct BlockModeWrapper<C: BlockCipher, M: BlockMode<C>, P: Padding<C::BlockSize>> {
    inner: M,
    buffer: BlockBuffer<C::BlockSize>,
    _pd: PhantomData<(C, P)>,
}

impl<C, M, P> FromBlockCipherNonce for BlockModeWrapper<C, M, P>
where
    C: BlockCipher, M: BlockMode<C> + FromBlockCipherNonce, P: Padding<C::BlockSize>,
{
    type BlockCipher = M::BlockCipher;
    type NonceSize = M::NonceSize;

    fn from_block_cipher_nonce(
        cipher: Self::BlockCipher,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self {
        Self {
            inner: M::from_block_cipher_nonce(cipher, nonce),
            buffer: Default::default(),
            _pd: Default::default(),
        }
    }
}

impl<C, M, P> BlockModeWrapper<C, M, P>
where
    C: BlockCipher, M: BlockMode<C>, P: Padding<C::BlockSize>,
{
    /// Encrypt part of a plaintext.
    ///
    /// The method encrypts plaintext in `data`, writes the resulting plaintext
    /// into `out_buf`, and returns it in the `Ok` variant. If whole message
    /// can not be processed, it caches ciphertext leftovers into inner buffer
    /// for future use.
    ///
    /// It's recommended for `out_buf` to be at least one block longer than
    /// `data`, otherwise the method can return `Err(InvalidLength)` if there is
    /// not enough space for encrypted blocks.
    #[inline]
    pub fn encrypt_part<'a>(
        &mut self, plaintext: &[u8], out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], InvalidLength> {
        let Self { inner, buffer, .. } = self;
        buffer.block_mode_processing(
            plaintext,
            out_buf,
            |blocks| inner.encrypt_blocks(blocks),
        ).map_err(|_| InvalidLength)
    }

    /// Decrypt part of a ciphertext.
    ///
    /// The method decrypts ciphertext in `data`, writes the resulting ciphertext
    /// into `out_buf`, and returns it in the `Ok` variant. If whole message
    /// can not be processed, it caches ciphertext leftovers into inner buffer
    /// for future use.
    ///
    /// It's recommended for `out_buf` to be at least one block longer than
    /// `data`, otherwise the method can return `Err(InvalidLength)` if there is
    /// not enough space for encrypted blocks.
    #[inline]
    pub fn decrypt_part<'a>(
        &mut self, ciphertext: &[u8], out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], InvalidLength> {
        let Self { inner, buffer, .. } = self;
        buffer.block_mode_processing(
            ciphertext,
            out_buf,
            |blocks| inner.decrypt_blocks(blocks),
        ).map_err(|_| InvalidLength)
    }

    /// Pad and encrypt plaintext.
    ///
    /// The method pads plaintext in `data` and encrypts it writing the resulting
    /// ciphertext into `out_buf`.
    ///
    /// It's recommended for `out_buf` to be at least one block longer than
    /// `data`, otherwise the method can return `Err(InvalidLength)` if there is
    /// not enough space for encrypted blocks.
    #[inline]
    pub fn encrypt_final<'a>(
        mut self, plaintext: &[u8], out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], InvalidLength> {
        let Self { inner, buffer, .. } = &mut self;
        let res_len = buffer.block_mode_processing(
            plaintext,
            out_buf,
            |blocks| inner.encrypt_blocks(blocks),
        ).map_err(|_| InvalidLength)?.len();
        let final_block = buffer.pad_with::<P>();
        inner.encrypt_blocks(from_mut(final_block));
        let bs = C::BlockSize::USIZE;
        let buf = out_buf
            .get_mut(res_len..)
            .and_then(|buf| buf.get_mut(..bs))
            .ok_or(InvalidLength)?;
        buf.copy_from_slice(final_block);
        out_buf.get(..bs + res_len).ok_or(InvalidLength)
    }

    /// Pad and encrypt plaintext.
    ///
    /// The method pads plaintext in `data` and encrypts it writing the resulting
    /// ciphertext into `out_buf`.
    ///
    /// It's recommended for `out_buf` to be at least one block longer than
    /// `data`, otherwise the method can return `Err(InvalidLength)` if there is
    /// not enough space for encrypted blocks.
    #[inline]
    pub fn decrypt_final<'a>(
        mut self, ciphertext: &[u8], out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], InvalidLength> {
        let Self { inner, buffer, .. } = &mut self;
        let res_len = buffer.block_mode_processing(
            ciphertext,
            out_buf,
            |blocks| inner.decrypt_blocks(blocks),
        ).map_err(|_| InvalidLength)?.len();
        let final_block = buffer.pad_with::<P>();
        inner.encrypt_blocks(from_mut(final_block));
        let bs = C::BlockSize::USIZE;
        let buf = out_buf
            .get_mut(res_len..)
            .and_then(|buf| buf.get_mut(..bs))
            .ok_or(InvalidLength)?;
        buf.copy_from_slice(final_block);
        out_buf.get(..bs + res_len).ok_or(InvalidLength)
    }
}
