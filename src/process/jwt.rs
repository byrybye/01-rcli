
use anyhow::{Ok, Result};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    aud: String, // Optional 代表这个JWT的接收对象
    exp: usize,  // Required 是一个时间戳，代表这个JWT的过期时间    
    sub: String, // Optional 代表着此 JWT 的主角
}

pub fn jwt_sign(sub:String, aud:String, exp: i64)->Result<String>
{
    let key = b"secret";
    let claims = Claims {
        aud: aud,
        exp: (chrono::Local::now().timestamp() + exp) as usize,        
        sub: sub,
    };
    let mut head: Header = Header::new(Algorithm::HS256);
    head.typ = Some("jwt".to_string());
    let token = encode(&head, &claims, &EncodingKey::from_secret(key))?;
    Ok(token)
}

pub fn jwt_verify(token:String, sub:String, aud:String,) ->Result<Claims>{
    let key = b"secret";
    let mut validation = Validation::new(Algorithm::HS256);
    validation.sub = Some(sub);    
    validation.set_audience(&[aud]);
    validation.set_required_spec_claims(&["exp", "sub", "aud"]);
    println!("{}", token);
    let token = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(key),
        &validation,
    )?;
    Ok(token.claims)
}

