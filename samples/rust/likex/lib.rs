// SPDX-License-Identifier: GPL-2.0
use kernel::prelude::*;
use alloc::vec::Vec;
use core::mem;
pub(crate) struct Bitmap {
    data: Vec<u8>,
    size: usize,
}

impl Bitmap {
    pub(crate) fn new(size: usize) -> Result<Self> {
        let mut data = Vec::try_with_capacity((size + 7) / 8)?;
	data.try_push(unsafe { mem::zeroed() })?;
        Ok(Self { data, size })
    }

    pub(crate) fn set(&mut self, index: usize) {
        let byte_index = index / 8;
        let bit_index = index % 8;
        self.data[byte_index] |= 1 << bit_index;
    }

    pub(crate) fn clear(&mut self, index: usize) {
        let byte_index = index / 8;
        let bit_index = index % 8;
        self.data[byte_index] &= !(1 << bit_index);
    }

    pub(crate) fn get(&self, index: usize) -> bool {
        let byte_index = index / 8;
        let bit_index = index % 8;
        (self.data[byte_index] & (1 << bit_index)) != 0
    }

    pub(crate) fn size(&self) -> usize {
        self.size
    }
}
