use itertools::Itertools;
use std::{
    collections::{BTreeSet, HashSet},
    ops::{Deref, DerefMut},
};

#[derive(Debug, Clone)]
pub(crate) struct Combinations(Vec<BTreeSet<u16>>);

impl Combinations {
    /// Create a new `Combinations` instance.
    /// If a cache is provided, its combinations are prioritized (ordered first),
    /// and the rest are appended after.
    pub(crate) fn new(participants: Vec<u16>, r: u16, cache: &Option<Self>) -> Self {
        // Step 1: Generate all r-length combinations from the participant list
        let all_combinations: Vec<BTreeSet<u16>> = participants
            .iter()
            .combinations(r as usize)
            .map(|combo| combo.into_iter().map(|&id| id).collect::<BTreeSet<u16>>())
            .collect();

        // Step 2: If a cache is provided, prioritize cached combinations
        if let Some(combinations_cache) = cache {
            let in_cache: HashSet<BTreeSet<u16>> = combinations_cache.0.iter().cloned().collect();
            let mut ordered = Vec::new();
            for comb in all_combinations.iter() {
                if !in_cache.contains(comb) {
                    ordered.push(comb.clone());
                }
            }
            for comb in combinations_cache.iter() {
                ordered.push(comb.clone());
            }

            Combinations(ordered)
        } else {
            // No cache provided, return all
            Combinations(all_combinations)
        }
    }

    /// Filter out any combinations that contain error IDs.
    pub(crate) fn filter_error_ids(&mut self, error_ids: &BTreeSet<u16>) {
        self.0.retain(|set| set.is_disjoint(error_ids));
    }
}

impl Deref for Combinations {
    type Target = Vec<BTreeSet<u16>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for Combinations {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn bset(set: &[u16]) -> BTreeSet<u16> {
        set.iter().cloned().collect()
    }

    #[test]
    fn test_combinations_with_cache_priority() {
        // Step 1: Generate all combinations
        let full = Combinations::new(vec![1, 2, 3, 4, 5], 3, &None);

        // Assert all combinations match expected
        let expected_all: Vec<BTreeSet<u16>> = vec![
            bset(&[1, 2, 3]),
            bset(&[1, 2, 4]),
            bset(&[1, 2, 5]),
            bset(&[1, 3, 4]),
            bset(&[1, 3, 5]),
            bset(&[1, 4, 5]),
            bset(&[2, 3, 4]),
            bset(&[2, 3, 5]),
            bset(&[2, 4, 5]),
            bset(&[3, 4, 5]),
        ];
        assert_eq!(&*full, &expected_all);

        // Step 2: Define cache as a slice of the original
        let cache = Combinations(full[5..].to_vec());

        // Assert cache matches expected
        let expected_cache: Vec<BTreeSet<u16>> = vec![
            bset(&[1, 4, 5]),
            bset(&[2, 3, 4]),
            bset(&[2, 3, 5]),
            bset(&[2, 4, 5]),
            bset(&[3, 4, 5]),
        ];
        assert_eq!(&*cache, &expected_cache);

        // Step 3: Regenerate combinations with cache
        let prioritized = Combinations::new(vec![1, 2, 3, 4, 5], 3, &Some(cache.clone()));

        // Assert final ordering (cache first, rest after)
        let expected_final: Vec<BTreeSet<u16>> = vec![
            bset(&[1, 2, 3]),
            bset(&[1, 2, 4]),
            bset(&[1, 2, 5]),
            bset(&[1, 3, 4]),
            bset(&[1, 3, 5]),
            bset(&[1, 4, 5]),
            bset(&[2, 3, 4]),
            bset(&[2, 3, 5]),
            bset(&[2, 4, 5]),
            bset(&[3, 4, 5]),
        ];
        assert_eq!(&*prioritized, &expected_final);
    }
}
