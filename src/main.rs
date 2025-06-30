use axum::{extract::Json, response::IntoResponse, routing::post, Router};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
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

fn error_response(message: &str) -> Json<ApiResponse<serde_json::Value>> {
    Json(ApiResponse {
        success: false,
        data: None,
        error: Some(message.to_string()),
    })
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

    let mint = match req.mint.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return error_response("Invalid mint address"),
    };

    let authority = match req.mint_authority.parse::<Pubkey>() {
        Ok(auth) => auth,
        Err(_) => return error_response("Invalid mint auth"),
    };

    let instruction = match token_instruction::initialize_mint(&program_id, &mint, &authority, None, req.decimals) {
        Ok(i) => i,
        Err(_) => return error_response("Failed to create instruction"),
    };

    let encoded_data = if instruction.data.is_empty() {
        return error_response("Instruction data is empty — possibly invalid inputs");
    } else {
        general_purpose::STANDARD.encode(&instruction.data)
    };

    Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts,
            "instruction_data": encoded_data,
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
    let mint = match req.mint.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return error_response("Invalid mint address"),
    };

    let destination = match req.destination.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return error_response("Invalid destination address"),
    };

    let authority = match req.authority.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return error_response("Invalid authority address"),
    };


    let instruction = match token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ) {
        Ok(i) => i,
        Err(_) => return error_response("Failed to construct mint_to instruction"),
    };

       let encoded_data = if instruction.data.is_empty() {
        return error_response("Instruction data is empty — possibly invalid inputs");
    } else {
        general_purpose::STANDARD.encode(&instruction.data)
    };


    Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts,
            "instruction_data": encoded_data,
        })),
        error: None,
    })
}


#[derive(Deserialize)]
pub struct SignMessageRequest {
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
        Err(_) => error_response("Invalid base58 secret format"),
    }
}

#[derive(Deserialize)]
pub struct VerifyMessageRequest {
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
        _ => error_response("Invalid pubkey or signature format"),
    }
}

#[derive(Deserialize)]
pub struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

async fn send_sol(Json(req): Json<SendSolRequest>) -> impl IntoResponse {
    let from = match req.from.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return error_response("Invalid sender address"),
    };
    let to = match req.to.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return error_response("Invalid recipient address"),
    };

    let instruction = system_instruction::transfer(&from, &to, req.lamports);

     let encoded_data = if instruction.data.is_empty() {
        return error_response("Instruction data is empty — possibly invalid inputs");
    } else {
        general_purpose::STANDARD.encode(&instruction.data)
    };

    Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts.iter().map(|a| a.pubkey.to_string()).collect::<Vec<_>>(),
            "instruction_data": encoded_data,
        })),
        error: None,
    })
}


#[derive(Deserialize)]
pub struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

async fn send_token(Json(req): Json<SendTokenRequest>) -> impl IntoResponse {
    let destination = match req.destination.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => return error_response("Invalid destination address"),
    };
    let mint = match req.mint.parse::<Pubkey>() {
        Ok(m) => m,
        Err(_) => return error_response("Invalid mint address"),
    };
    let owner = match req.owner.parse::<Pubkey>() {
        Ok(own) => own,
        Err(_) => return error_response("Invalid owner address"),
    };

    let instruction = match token_instruction::transfer(
        &spl_token::id(),
        &mint,
        &destination,
        &owner,
        &[],
        req.amount,
    ) {
        Ok(i) => i,
        Err(_) => return error_response("Failed to construct token transfer instruction"),
    };

    let encoded_data = if instruction.data.is_empty() {
        return error_response("Instruction data is empty — possibly invalid inputs");
    } else {
        general_purpose::STANDARD.encode(&instruction.data)
    };

    Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts,
            "instruction_data": encoded_data,
        })),
        error: None,
    })
}


