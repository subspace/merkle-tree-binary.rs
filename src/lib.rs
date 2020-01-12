use std::cmp::Ordering;

pub struct Tree<'items> {
    items: &'items [Vec<u8>],
    tree: Vec<Vec<Vec<u8>>>,
}

impl<'items> Tree<'items> {
    pub fn new<HashFunction>(items: &[Vec<u8>], hash_function: HashFunction) -> Tree
    where
        HashFunction: Fn(&[u8]) -> Vec<u8>,
    {
        let tree = Default::default();
        let mut tree = Tree { items, tree };
        tree.build_tree(items, hash_function);
        tree
    }

    fn get_proof(&self, target_item: &[u8]) -> Result<Vec<u8>, ()> {
        for (i, item) in self.items.iter().enumerate() {
            if item.as_slice().cmp(target_item) == Ordering::Equal {
                return Ok(self.get_proof_for(i));
            }
        }

        Err(())
    }

    fn get_root(&self) -> &[u8] {
        return self.tree.last().unwrap().first().unwrap();
    }

    fn build_tree<HashFunction>(&mut self, items: &[Vec<u8>], hash_function: HashFunction)
    where
        HashFunction: Fn(&[u8]) -> Vec<u8>,
    {
        // TODO: This is inefficient
        self.tree.push(items.to_owned());

        if items.len() == 1 {
            return;
        }
        let mut new_items: Vec<Vec<u8>> = Default::default();
        for index in (0..items.len()).step_by(2) {
            // TODO: This is inefficient, we shouldn't require mutable things here just to compute hash
            let mut item1 = items.get(index).unwrap().clone();
            let mut item2 = items.get(index + 1).unwrap_or(&item1).to_owned();
            item1.append(&mut item2);
            new_items.push(hash_function(&item1));
        }

        self.build_tree(&new_items, hash_function);
    }

    fn get_proof_for(&self, item_index: usize) -> Vec<u8> {
        let mut proof = Vec::<u8>::new();
        let tree = &self.tree;
        let levels = tree.len() - 1;

        let mut current_level = 0;
        let mut right = item_index % 2;
        let mut index = item_index - right;

        // Last level is the root itself, hence we exclude it
        while current_level < levels {
            let tree_level = &tree[current_level];
            // if current element is to the right - take left element, otherwise try to take right one and fallback to left if not present (unbalanced tree)
            let mut other_item = if right == 1 {
                tree_level.get(index).unwrap().to_owned()
            } else {
                tree_level
                    .get(index + 1)
                    .unwrap_or(&tree_level[index])
                    .to_owned()
            };
            proof.push(right as u8);
            proof.append(&mut other_item);
            right = (index / 2) % 2;
            index = index / 2 - right;
            current_level += 1;
        }

        return proof;
    }

    pub fn check_proof<HashFunction>(
        root: &[u8],
        proof: &[u8],
        target_item: &[u8],
        hash_function: HashFunction,
    ) -> bool
    where
        HashFunction: Fn(&[u8]) -> Vec<u8>,
    {
        if root.cmp(&target_item) == Ordering::Equal && proof.is_empty() {
            return true;
        }
        let item_length = target_item.len();
        if proof.len() % (item_length + 1) > 0 {
            return false;
        }
        let proof_step = item_length + 1;
        let mut target_item = target_item.to_owned();
        for i in (0..proof.len()).step_by(proof_step) {
            let mut item = proof[(i + 1)..(i + proof_step)].to_vec();
            // TODO: This is inefficient, we shouldn't require mutable things here just to compute hash
            println!("Byte {}", proof[i]);
            target_item = hash_function(if proof[i] == 1 {
                item.append(&mut target_item);
                println!("item {:?}", &item);
                &item
            } else {
                target_item.append(&mut item);
                println!("target item {:?}", &target_item);
                &target_item
            });
        }

        println!("cmp\n{:?}\n{:?}", &root, &target_item);
        return root.cmp(&target_item) == Ordering::Equal;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use rand::Rng;
    use sha1::Sha1;

    fn sha1(input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(input);
        hasher.digest().bytes().to_vec()
    }

    #[test]
    fn one_item() {
        let item = rand::thread_rng().gen::<[u8; 20]>().to_vec();
        let items = vec![item.clone()];
        let tree = Tree::new(&items, sha1);
        assert_eq!(tree.get_root(), item.as_slice());
        assert!(tree
            .get_proof(&item)
            .expect("Failed to get proof for single item")
            .is_empty());
        assert_eq!(Tree::check_proof(&item, &vec![], &item, sha1), true);
        assert_eq!(Tree::check_proof(&item, &vec![1u8], &item, sha1), false);
    }

    #[test]
    fn two_items() {
        let item1 = hex::decode("73b824aa6091c14ce5d72d17b4e84317afba4cee").unwrap();
        let item2 = hex::decode("93158d5aa8dda6d8fe8db6b3c80448312c4ed52c").unwrap();
        let items = vec![item1.clone(), item2.clone()];
        let root = hex::decode("f7a66262edf364a8d23f487cb59d37446ec0fbd1").unwrap();
        let proof1 = hex::decode("0093158d5aa8dda6d8fe8db6b3c80448312c4ed52c").unwrap();
        let proof2 = hex::decode("0173b824aa6091c14ce5d72d17b4e84317afba4cee").unwrap();
        let tree = Tree::new(&items, sha1);
        assert_eq!(tree.get_root(), root.as_slice());
        assert_eq!(
            tree.get_proof(&item1)
                .expect("Failed to get proof for item 1/2"),
            proof1
        );
        assert_eq!(
            tree.get_proof(&item2)
                .expect("Failed to get proof for item 2/2"),
            proof2
        );
        assert_eq!(Tree::check_proof(&root, &proof1, &item1, sha1), true);
        assert_eq!(Tree::check_proof(&root, &proof2, &item2, sha1), true);
        assert_eq!(Tree::check_proof(&root, &proof2, &item1, sha1), false);
        assert_eq!(Tree::check_proof(&root, &proof1, &item2, sha1), false);
    }

    #[test]
    fn three_items() {
        let item1 = hex::decode("8f86ba7f7481fa30716b0bc5b37650bdf4999204").unwrap();
        let item2 = hex::decode("025e1d661e91e1c55ce9091c89512d97251c7b61").unwrap();
        let item3 = hex::decode("bbed8ca2b401f13ab821d4f24f58a39bdabcd683").unwrap();
        let items = vec![item1.clone(), item2.clone(), item3.clone()];
        let root = hex::decode("9d0192f5119f2c2654d9dc73233c61c0c0a26aa3").unwrap();
        let proof1 = hex::decode(
            "00025e1d661e91e1c55ce9091c89512d97251c7b6100c99a4bc9d9b292a428fc71759c83e967bf3559ca",
        )
        .unwrap();
        let proof2 = hex::decode(
            "018f86ba7f7481fa30716b0bc5b37650bdf499920400c99a4bc9d9b292a428fc71759c83e967bf3559ca",
        )
        .unwrap();
        let proof3 = hex::decode(
            "00bbed8ca2b401f13ab821d4f24f58a39bdabcd68301f0b509ed572e51c041f1f4b902b4aa55899c205d",
        )
        .unwrap();
        let tree = Tree::new(&items, sha1);
        assert_eq!(tree.get_root(), root.as_slice());
        assert_eq!(
            tree.get_proof(&item1)
                .expect("Failed to get proof for item 1/3"),
            proof1
        );
        assert_eq!(
            tree.get_proof(&item2)
                .expect("Failed to get proof for item 2/3"),
            proof2
        );
        assert_eq!(
            tree.get_proof(&item3)
                .expect("Failed to get proof for item 3/3"),
            proof3
        );
        assert_eq!(Tree::check_proof(&root, &proof1, &item1, sha1), true);
        assert_eq!(Tree::check_proof(&root, &proof2, &item2, sha1), true);
        assert_eq!(Tree::check_proof(&root, &proof3, &item3, sha1), true);
        assert_eq!(Tree::check_proof(&root, &proof3, &item1, sha1), false);
        assert_eq!(Tree::check_proof(&root, &proof2, &item3, sha1), false);
        assert_eq!(Tree::check_proof(&root, &proof1, &item2, sha1), false);
    }

    #[test]
    fn randomized_items() {
        let items = (0..1000)
            .map(|_| rand::thread_rng().gen::<[u8; 20]>().to_vec())
            .collect::<Vec<Vec<u8>>>();
        let tree = Tree::new(&items, sha1);
        for item in &items {
            assert!(Tree::check_proof(
                tree.get_root(),
                &tree.get_proof(item).unwrap(),
                item,
                sha1
            ));
        }
    }
}
