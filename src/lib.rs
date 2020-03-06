#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DecodedIdToken {
    aud: String,
    auth_time: usize,
    exp: usize,
    iat: usize,
    iss: String,
    sub: String,
}

pub async fn verify_id_token_with_project_id(
    token: &str,
    project_id: &str,
) -> Result<DecodedIdToken, Box<dyn std::error::Error>> {
    let header = match jsonwebtoken::decode_header(token) {
        Ok(output) => output,
        Err(_) => return Err(std::boxed::Box::from(String::from("Header"))),
    };

    if header.alg != jsonwebtoken::Algorithm::RS256 {
        return Err(std::boxed::Box::from(String::from("Algorithm")));
    }

    let kid = match header.kid {
        Some(value) => value,
        None => return Err(std::boxed::Box::from(String::from("Kid"))),
    };

    let public_keys = reqwest::get(
        "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
    )
    .await?
    .json::<std::collections::HashMap<String, String>>()
    .await?;

    if !public_keys.contains_key(&kid) {
        return Err(std::boxed::Box::from(String::from("Public Keys Kid")));
    }

    let public_key = match public_keys.get(&kid) {
        Some(value) => value,
        None => return Err(std::boxed::Box::from(String::from("Public Key"))),
    };

    let aud: std::collections::HashSet<String> = vec![project_id.to_string()].into_iter().collect();

    let validation = jsonwebtoken::Validation {
        aud: Some(aud),
        iss: Some(format!("https://securetoken.google.com/{}", project_id)),
        ..jsonwebtoken::Validation::default()
    };

    let decoded_id_token = match jsonwebtoken::decode::<DecodedIdToken>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret(public_key.as_bytes()),
        &validation,
    ) {
        Ok(value) => value.claims,
        Err(_) => return Err(std::boxed::Box::from(String::from("Decoded Id Token"))),
    };

    Ok(decoded_id_token)
}
