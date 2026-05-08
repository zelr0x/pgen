#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct MutByteSet([u64; 4]);

impl MutByteSet {
    pub(crate) const fn new(bytes: &[u8]) -> Self {
        let arr: [u64; 4] = [0; 4];
        let mut bs: MutByteSet = MutByteSet(arr);
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            bs.insert(b);
            i += 1;
        }
        bs
    }

    pub(crate) const fn contains(&self, byte: u8) -> bool {
        let idx = (byte / 64) as usize;
        let bit = byte % 64;
        (self.0[idx] & (1u64 << bit)) != 0
    }

    pub(crate) const fn insert(&mut self, b: u8) {
        let idx = (b / 64) as usize;
        let bit = b % 64;
        self.0[idx] |= 1u64 << bit;
    }

    pub(crate) const fn remove(&mut self, byte: u8) {
        let idx = (byte / 64) as usize;
        let bit = byte % 64;
        self.0[idx] &= !(1u64 << bit);
    }

    pub(crate) const fn len(&self) -> usize {
        let bytes = self.0;
        let mut i = 0;
        let mut sum = 0;
        while i < bytes.len() {
            sum += bytes[i].count_ones() as usize;
            i += 1
        }
        sum
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<ByteSet> for MutByteSet {
    fn from(bs: ByteSet) -> Self {
        MutByteSet(bs.0.0)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ByteSet(MutByteSet);

impl ByteSet {
    pub(crate) const fn new(bytes: &[u8]) -> Self {
        ByteSet(MutByteSet::new(bytes))
    }

    pub(crate) const fn diff_slice(&self, bytes: &[u8]) -> Self {
        let mut bs = self.0;
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            bs.remove(b);
            i += 1;
        }
        ByteSet(bs)
    }

    pub(crate) const fn contains(&self, byte: u8) -> bool {
        self.0.contains(byte)
    }

    #[allow(dead_code)]
    pub(crate) const fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<MutByteSet> for ByteSet {
    fn from(mbs: MutByteSet) -> Self {
        ByteSet(mbs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mbs_works() {
        let mut set = MutByteSet::default();
        for b in 0..=255 {
            assert!(!set.contains(b));
            set.insert(b);
            assert!(set.contains(b));
            set.remove(b);
            assert!(!set.contains(b));
        }
    }

    #[test]
    fn diff_slice_works() {
        let mut set = MutByteSet::default();
        let first = b'a';
        let last = b'j';
        for b in first..=last {
            set.insert(b);
        }
        let mut set = ByteSet(set);
        for b in first..=last {
            assert!(set.contains(b));
        }
        let first2 = first + 2;
        let last2 = last - 2;
        let to_rem = first2..=last2;
        let v: Vec<u8> = to_rem.clone().collect();
        set = set.diff_slice(&v);
        for b in first..=last {
            assert_eq!(set.contains(b), !to_rem.contains(&b));
        }
    }
}
