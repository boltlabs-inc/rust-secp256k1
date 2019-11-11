//extern crate bitcoin_hashes;
extern crate secp256k1;

//use bitcoin_hashes::{sha256, Hash};
use secp256k1::{Error, Message, PublicKey, Secp256k1, Signing, SecretKey, PartialSignature};

//fn verify<C: Verification>(secp: &Secp256k1<C>, msg: &[u8], sig: [u8; 64], pubkey: [u8; 33]) -> Result<bool, Error> {
//    let msg = sha256::Hash::hash(msg);
//    let msg = Message::from_slice(&msg)?;
//    let sig = Signature::from_compact(&sig)?;
//    let pubkey = PublicKey::from_slice(&pubkey)?;
//
//    Ok(secp.verify(&msg, &sig, &pubkey).is_ok())
//}

//fn sign<C: Signing>(secp: &Secp256k1<C>, msg: &[u8], seckey: [u8; 32]) -> Result<Signature, Error> {
//    let msg = sha256::Hash::hash(msg);
//    let msg = Message::from_slice(&msg)?;
//    let seckey = SecretKey::from_slice(&seckey)?;
//    Ok(secp.sign(&msg, &seckey))
//}

fn partial_sign<C: Signing>(secp: &Secp256k1<C>, nonce32: &[u8], seckey: [u8; 32]) -> Result<PartialSignature, Error> {
    // let msg = sha256::Hash::hash(msg);
    let nonce = Message::from_slice(&nonce32)?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.partial_sign(&nonce, &seckey))
}


fn main() {
    let secp = Secp256k1::new();

    let seckey = [59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28];
    let pubkey = [2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91, 141, 134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54];
    let nonce = b"This is some random four message";

    let partial_sig = partial_sign(&secp, nonce, seckey).unwrap();

    println!("Partial sig bytes: {}", partial_sig);

    // let serialize_sig = signature.serialize_compact();

    //assert!(verify(&secp, msg, serialize_sig, pubkey).unwrap());
}
