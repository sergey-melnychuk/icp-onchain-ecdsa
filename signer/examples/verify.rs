use k256::ecdsa::signature::Verifier;
use k256::ecdsa::Signature as Sig;
use k256::ecdsa::VerifyingKey as Key;

fn main() {
    let args = std::env::args()
        .into_iter()
        .skip(1)
        .take(3)
        .collect::<Vec<_>>();
    if args.len() != 3 {
        eprintln!("usage: verify <msg> <sig> <key>");
        std::process::exit(1);
    }

    let (msg, sig, key) = (&args[0], &args[1], &args[2]);
    let msg = msg.as_bytes();
    let sig = hex::decode(&sig).expect("failed to hex-decode signature");
    let key = hex::decode(&key).expect("failed to hex-decode public key");

    let signature =
        Sig::try_from(sig.as_slice()).expect("failed to deserialize signature");
    let is_valid = Key::from_sec1_bytes(&key)
        .expect("failed to deserialize sec1 encoding into public key")
        .verify(&msg, &signature)
        .is_ok();
    println!("  OK: {is_valid}");
}
