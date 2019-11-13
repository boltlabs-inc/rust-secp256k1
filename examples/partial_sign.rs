extern crate bitcoin_hashes;
extern crate secp256k1;

use bitcoin_hashes::{sha256, Hash};
use secp256k1::{Error, Message, PublicKey, Secp256k1, Signing, SecretKey, Signature, PartialSignature, Verification};

fn sign<C: Signing>(secp: &Secp256k1<C>, msg: &[u8], seckey: [u8; 32]) -> Result<Signature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.sign(&msg, &seckey))
}

// compute a presignature
fn partial_sign<C: Signing>(secp: &Secp256k1<C>, nonce32: &[u8], seckey: [u8; 32]) -> Result<PartialSignature, Error> {
    let msg = sha256::Hash::hash(nonce32);
    let nonce = Message::from_slice(&msg)?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.partial_sign(&nonce, &seckey))
}

// complete sign
fn complete_sign<C: Signing>(secp: &Secp256k1<C>, msg: &[u8], partial_sig: [u8; 96]) -> Result<Signature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let partial_sig = PartialSignature::from_compact(&partial_sig)?;
    Ok(secp.compute_sign(&msg, &partial_sig))
}

// verify signature
fn verify<C: Verification>(secp: &Secp256k1<C>, msg: &[u8], sig: [u8; 64], pubkey: [u8; 33]) -> Result<bool, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let sig = Signature::from_compact(&sig)?;
    let pubkey = PublicKey::from_slice(&pubkey)?;

    Ok(secp.verify(&msg, &sig, &pubkey).is_ok())
}

fn rerandomize<C: Signing>(secp: &Secp256k1<C>, rand: &[u8], sig: [u8; 64]) -> Result<Signature, Error> {
    let msg = sha256::Hash::hash(rand);
    let rand = Message::from_slice(&msg)?;
    let sig = Signature::from_compact(&sig)?;
    Ok(secp.rerandomize_sig(&rand, &sig))
}


fn main() {
    let secp = Secp256k1::new();

    let seckey = [59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28];
    let pubkey = [2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91, 141, 134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54];
    let nonce = b"Random seed for picking nonces";
    let msg = b"Random message to sign";

    let partial_sig = partial_sign(&secp, nonce, seckey.clone()).unwrap();

    println!("Partial sig bytes: {}", partial_sig);

    let ser_partial_sig = partial_sig.serialize_compact();

    let signature = complete_sign(&secp, msg, ser_partial_sig).unwrap();

    let serialize_sig = signature.serialize_compact();

    println!("Output sig 0: {:?}", signature);

//    let signature1 = sign(&secp, msg, seckey.clone()).unwrap();
//    let serialize_sig1 = signature1.serialize_compact();
//
//    println!("Output sig 1: {:?}", signature1);

    assert!(verify(&secp, msg, serialize_sig, pubkey).unwrap());

    println!("Successfully verified signature!");

    let rand = [92, 253, 80, 231, 48, 193, 182, 87, 119, 152, 225, 241, 38, 178, 26, 7, 215, 111, 2, 19, 149, 160, 63, 96, 46, 73, 11, 106, 189, 116, 146, 2];
    let new_signature = rerandomize(&secp, &rand, serialize_sig).unwrap();

    println!("Output sig 1: {:?}", new_signature);
    let serialize_sig1 = new_signature.serialize_compact();

    //assert!(verify(&secp, msg, serialize_sig1, pubkey).unwrap());

}
