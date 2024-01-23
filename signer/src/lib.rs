use std::str::FromStr;

use candid::{CandidType, Deserialize, Nat, Principal};
use ic_cdk::{
    api::management_canister::ecdsa::{EcdsaCurve, EcdsaKeyId},
    export::serde::Serialize,
    update,
};

const MGMT_CANISTER_ID: &str = "aaaaa-aa";
const ECDSA_KEY_NAME: &str = "dfx_test_key";
const ECDSA_SIGN_CYCLES: u64 = 26_153_846_153;

#[derive(CandidType, Serialize, Debug)]
struct EcdsaPublicKeyRequest {
    pub canister_id: Option<Principal>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct EcdsaPublicKeyResponse {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[update]
async fn pkey(path: Vec<Nat>) -> Result<String, String> {
    let derivation_path =
        path.into_iter().map(|nat| nat.0.to_bytes_be()).collect();

    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: ECDSA_KEY_NAME.to_owned(),
    };

    let request = EcdsaPublicKeyRequest {
        canister_id: None,
        derivation_path,
        key_id,
    };

    let id = Principal::from_str(MGMT_CANISTER_ID).unwrap();

    let (res,): (EcdsaPublicKeyResponse,) =
        ic_cdk::call(id, "ecdsa_public_key", (request,))
            .await
            .map_err(|e| format!("ecdsa_public_key failed: {}", e.1))?;

    Ok(hex::encode(res.public_key))
}

#[derive(CandidType, Serialize, Debug)]
struct EcdsaSignRequest {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct EcdsaSignResponse {
    pub signature: Vec<u8>,
}

#[update]
async fn sign(path: Vec<Nat>, hash: String) -> Result<String, String> {
    let hash =
        hex::decode(hash).map_err(|e| format!("invalid input hash: {}", e))?;

    let derivation_path =
        path.into_iter().map(|nat| nat.0.to_bytes_be()).collect();

    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: ECDSA_KEY_NAME.to_owned(),
    };

    let request = EcdsaSignRequest {
        message_hash: hash,
        derivation_path,
        key_id,
    };

    let id = Principal::from_str(MGMT_CANISTER_ID).unwrap();

    let (response,): (EcdsaSignResponse,) =
        ic_cdk::api::call::call_with_payment(
            id,
            "sign_with_ecdsa",
            (request,),
            ECDSA_SIGN_CYCLES,
        )
        .await
        .map_err(|e| format!("sign_with_ecdsa failed: {}", e.1))?;

    Ok(hex::encode(response.signature))
}
