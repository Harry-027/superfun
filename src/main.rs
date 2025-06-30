use axum::{extract::Json, response::IntoResponse, routing::post, Router};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    signature::{Keypair as SolanaKeypair, Signer as SolanaSigner},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use base64::{engine::general_purpose, Engine as _};
use bs58;
use serde_json::Value;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub async fn generate_keypair() -> impl IntoResponse {
    let keypair = SolanaKeypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({ "pubkey": pubkey, "secret": secret })),
        error: None,
    })
}


#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

async fn create_token(Json(req): Json<CreateTokenRequest>) -> impl IntoResponse {
    let program_id = spl_token::id();
    let mint = req.mint.parse().unwrap();
    println!("mint: {}", req.mint_authority);
    let authority = req.mint_authority.parse().unwrap();

    let instruction = token_instruction::initialize_mint(
        &program_id,
        &mint,
        &authority,
        None,
        req.decimals,
    )
        .unwrap();

    Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts,
            "instruction_data": general_purpose::STANDARD.encode(&instruction.data),
        })),
        error: None,
    })
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token(Json(req): Json<MintTokenRequest>) -> impl IntoResponse {
    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &req.mint.parse().unwrap(),
        &req.destination.parse().unwrap(),
        &req.authority.parse().unwrap(),
        &[],
        req.amount,
    )
        .unwrap();

    Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts,
            "instruction_data": general_purpose::STANDARD.encode(&instruction.data),
        })),
        error: None,
    })
}


#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

pub async fn sign_message(Json(req): Json<SignMessageRequest>) -> impl IntoResponse {
    match bs58::decode(&req.secret).into_vec() {
        Ok(secret_bytes) => {
            if secret_bytes.len() != 32 {
                return Json(ApiResponse::<Value> {
                    success: false,
                    data: None,
                    error: Some("Secret key must be 32 bytes".to_string()),
                });
            }

            let signing_key = SigningKey::from_bytes(&secret_bytes.try_into().unwrap());
            let verifying_key = signing_key.verifying_key();
            let sig: Signature = signing_key.sign(req.message.as_bytes());

            Json(ApiResponse::<Value> {
                success: true,
                data: Some(serde_json::json!({
                    "signature": general_purpose::STANDARD.encode(sig.to_bytes()),
                    "public_key": bs58::encode(verifying_key.to_bytes()).into_string(),
                    "message": req.message,
                })),
                error: None,
            })
        }
        Err(_) => Json(ApiResponse::<Value> {
            success: false,
            data: None,
            error: Some("Invalid base58 secret key format".to_string()),
        }),
    }
}


#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

pub async fn verify_message(Json(req): Json<VerifyMessageRequest>) -> impl IntoResponse {
    match (
        bs58::decode(&req.pubkey).into_vec(),
        general_purpose::STANDARD.decode(&req.signature),
    ) {
        (Ok(pub_bytes), Ok(sig_bytes)) => {
            if pub_bytes.len() != 32 || sig_bytes.len() != 64 {
                return Json(ApiResponse::<Value> {
                    success: false,
                    data: None,
                    error: Some("Invalid pubkey or signature length".into()),
                });
            }

            let verifying_key = VerifyingKey::from_bytes(&pub_bytes.try_into().unwrap()).unwrap();
            let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());

            let valid = verifying_key.verify(req.message.as_bytes(), &signature).is_ok();

            Json(ApiResponse::<Value> {
                success: true,
                data: Some(serde_json::json!({
                    "valid": valid,
                    "message": req.message,
                    "pubkey": req.pubkey
                })),
                error: None,
            })
        }
        _ => Json(ApiResponse::<Value> {
            success: false,
            data: None,
            error: Some("Invalid pubkey or signature format".into()),
        }),
    }
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

async fn send_sol(Json(req): Json<SendSolRequest>) -> impl IntoResponse {
    let instruction = system_instruction::transfer(
        &req.from.parse().unwrap(),
        &req.to.parse().unwrap(),
        req.lamports,
    );

    Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts.iter().map(|a| a.pubkey.to_string()).collect::<Vec<_>>(),
            "instruction_data": general_purpose::STANDARD.encode(&instruction.data),
        })),
        error: None,
    })
}


#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

async fn send_token(Json(req): Json<SendTokenRequest>) -> impl IntoResponse {
    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &req.mint.parse().unwrap(),
        &req.destination.parse().unwrap(),
        &req.owner.parse().unwrap(),
        &[],
        req.amount,
    )
        .unwrap();

    Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts,
            "instruction_data": general_purpose::STANDARD.encode(&instruction.data),
        })),
        error: None,
    })
}


