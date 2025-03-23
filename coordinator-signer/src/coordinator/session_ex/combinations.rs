use itertools::Itertools;
use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
};

#[derive(Debug, Clone)]
pub(crate) struct Combinations(Vec<HashSet<u16>>);

impl Combinations {
    pub(crate) fn new(participants: Vec<u16>, r: u16) -> Self {
        let combinations = participants
            .iter()
            .combinations(r as usize)
            .map(|combo| combo.into_iter().map(|&id| id).collect::<HashSet<u16>>())
            .collect();

        Combinations(combinations)
    }

    pub(crate) fn filter_error_ids(&mut self, error_ids: &HashSet<u16>) {
        self.0.retain(|set| set.is_disjoint(error_ids));
    }
}

impl Deref for Combinations {
    type Target = Vec<HashSet<u16>>;

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

    #[test]
    fn test_combinations() {
        let combinations = Combinations::new(vec![1, 2, 3, 4, 5], 3);
        println!("{:?}", combinations);
    }
}
