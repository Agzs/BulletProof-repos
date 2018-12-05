// Create a rangeproof for a set of values.

extern crate rand;
use rand::thread_rng;

extern crate curve25519_dalek;
use curve25519_dalek::scalar::Scalar;

extern crate merlin;
use merlin::Transcript;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

fn multiple_proof_test() {

    println!("Running multiple bulletproof");

    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 16.
    let bp_gens = BulletproofGens::new(64, 16);

    // Four secret values we want to prove lie in the range [0, 2^32)
    let secrets = [4242344947u64, 3718732727u64, 2255562556u64, 2526146994u64];

    // The API takes blinding factors for the commitments.
    let blindings: Vec<_> = (0..4).map(|_| Scalar::random(&mut thread_rng())).collect();

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"doctest example");

    println!("Trying to generate multiple values bulletproof");

    // Create an aggregated 32-bit rangeproof and corresponding commitments.
    let (proof, commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &secrets,
        &blindings,
        32,
    ).expect("A real program could handle errors");
    
    let a: Vec<u8> = proof.to_bytes();
    let mut first = true;
    print!("proof = {{");
    for a in a.iter() {
        print!("{}{}",
                {if !first { ", " } else {first = false; ""}},
                a
                );
    }
    println!("}}");

    // print!("commitments = ");
    // let mut first = true;
    // for commitment in commitments.iter() {
    //     print!("{}{}",
    //             {if !first { ", " } else {first = false; ""}},
    //             commitment
    //             );
    // }
    // println!("");

    // Verification requires a transcript with identical initial state:
    let mut verifier_transcript = Transcript::new(b"doctest example");
    assert!(
        proof
            .verify_multiple(&bp_gens, &pc_gens, &mut verifier_transcript, &commitments, 32)
            .is_ok()
    );

    println!("Verifying multiple values proof successfully");
}

fn single_proof_test(){

    println!("Running single bulletproof");

    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

    // A secret value we want to prove lies in the range [0, 2^32)
    let secret_value = 1037578891u64;

    // The API takes a blinding factor for the commitment.
    let blinding = Scalar::random(&mut thread_rng());

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"doctest example");

    println!("Trying to generate single values bulletproof");

    // Create a 32-bit rangeproof.
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        32,
    ).expect("A real program could handle errors");

    let a: Vec<u8> = proof.to_bytes();
    let mut first = true;
    print!("proof = {{");
    for a in a.iter() {
        print!("{}{}",
                {if !first { ", " } else {first = false; ""}},
                a
                );
    }
    println!("}}");
    // println!("commitment = {}", committed_value);

    // Verification requires a transcript with identical initial state:
    let mut verifier_transcript = Transcript::new(b"doctest example");
    assert!(
        proof
            .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, 32)
            .is_ok()
    );

    println!("Verifying single values proof successfully");

}

fn main() {

    multiple_proof_test();
    println!("===============================================");
    single_proof_test();
}