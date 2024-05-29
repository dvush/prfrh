use alloy_rlp::Decodable;
use reth::primitives::trie::nodes::TrieNode;
use reth::primitives::trie::AccountProof;

pub fn pretty_print_proof(proof: &AccountProof) {
    println!("Proof");
    println!("Address     : {:?}", proof.address);
    println!("Info        : {:#?}", proof.info);
    println!("Storage Root: {:?}", proof.storage_root);
    println!("Account proof");
    for node in &proof.proof {
        let node = TrieNode::decode(&mut &node[..]).expect("proof decode");
        println!(" TrieNode: {:#?}", node);
    }
    println!("Storage proofs:");
    for storage_proof in &proof.storage_proofs {
        println!(" key:     {:?}", storage_proof.key);
        println!(" value:   {:?}", storage_proof.value);
        println!(" nibbles: {:?}", storage_proof.nibbles);
        for node in &storage_proof.proof {
            let node = TrieNode::decode(&mut &node[..]).expect("proof decode");
            println!("   TrieNode: {:#?}", node);
        }
    }
    println!("END Proof");
    println!();
}
