use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BinaryHeap};
use std::hash::Hash;
use std::iter::FromIterator;

#[derive(Debug)]
pub enum BinPackingError {
    OversizedItem,
}

#[derive(Clone, Copy, Debug)]
pub struct Item<T: Clone + Copy> {
    pub id: T,
    pub volume: usize,
}

impl<T: Clone + Copy> Ord for Item<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.volume.cmp(&other.volume)
    }
}

impl<T: Clone + Copy> PartialOrd for Item<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Clone + Copy> PartialEq for Item<T> {
    fn eq(&self, other: &Self) -> bool {
        self.volume == other.volume
    }
}

impl<T: Clone + Copy> Eq for Item<T> {}

#[derive(Clone, Copy, Debug)]
struct TreeKey((usize, usize));

impl Ord for TreeKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.0).1.cmp(&(other.0).1) {
            Ordering::Equal => (self.0).0.cmp(&(other.0).0),
            a => a,
        }
    }
}

impl PartialOrd for TreeKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TreeKey {
    fn eq(&self, other: &Self) -> bool {
        (self.0).0 == (other.0).0
    }
}

impl Eq for TreeKey {}

//The bin packing algorithm should fail if there's an item with a volume larger than the bin volume.
//Otherwise, keep going.
pub fn pack_bins<T: Hash + Eq + Clone + Copy + std::fmt::Debug>(
    bin_volume: usize,
    items: &[Item<T>],
) -> Result<Vec<Vec<Item<T>>>, BinPackingError> {
    //Checking if thing is valid.
    for item in items.iter() {
        if item.volume > bin_volume {
            return Err(BinPackingError::OversizedItem);
        }
    }
    let mut items = BinaryHeap::from_iter(items.iter());
    let mut tree = BTreeMap::new();

    tree.insert(Reverse(TreeKey((0, bin_volume))), vec![]);
    let mut index = 1;
    'main: while let Some(item) = items.pop() {
        let keys: Vec<_> = tree.keys().cloned().collect();
        for key in keys {
            let (id, key_volume) = (key.0).0;
            if item.volume <= key_volume {
                let mut vec = tree[&key].clone();
                vec.push(*item);
                tree.remove(&key);
                let consumed: usize = vec.iter().map(|items| items.volume).sum();
                tree.insert(Reverse(TreeKey((id, bin_volume - consumed))), vec);
                continue 'main;
            }
        }
        let key = TreeKey((index, bin_volume - item.volume));
        tree.insert(Reverse(key), vec![*item]);
        index += 1;
    }

    Ok(tree.iter().map(|(_, value)| value).cloned().collect())
}
