use std::{fmt, str::FromStr};
use regex::Regex; 
use clap::Parser;
use enum_dispatch::enum_dispatch;
use anyhow::Result;

use crate::CmdExector;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JwtSubCommand {
    #[command(name = "sign", about = "get a token")]
    Sign(JwtSignOpts),
    #[command(name = "verify", about = "verify a token")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(long)]
    pub sub: String,
    #[arg(long)]
    pub aud: String,
    #[arg( long, value_parser = verify_exp_format)]
    pub exp: String,
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(short, long)]
    pub token: String,
}


fn verify_exp_format(exp_ex: &str) -> Result<String, &'static str> {    
    //Err("File does not exist")
    Ok("".to_string())
}

impl CmdExector for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        println!("jwt sign");
        println!("{}", self.exp);
        Ok(())
    }
}

impl CmdExector for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        println!("jwt verify");
        println!("{}", self.token);
        Ok(())
    }
}


fn split_string_with_regex(s: &str) -> Result<(String, String), String> {  
    let re = Regex::new(r"^(\d+)([a-zA-Z])$").unwrap();  
    let captures = re.captures(s);  
    captures.ok_or_else(|| {  
        format!("Input string '{}' does not match the expected format of numbers followed by a single letter.", s)  
    }).and_then(|caps| {  
        // 确保至少有两个捕获组（数字和字母）  
        if caps.len() < 3 {  
            Err("Regular expression did not capture both number and letter as expected.".to_string())  
        } else {  
            // 提取数字和字母部分  
            let number_part = caps[1].to_string();  
            let letter_part = caps[2].to_string();  
            Ok((number_part, letter_part))  
        }  
    })  
}  

#[test]
fn test_split_string_with_regex() {  
    let s = "12345a";  
    match split_string_with_regex(&s) {  
        Ok((number, letter)) => {  
            println!("Number: {}, Letter: {}", number, letter);  
        },  
        Err(e) => {  
            println!("Error: {}", e);  
        }  
    }
    let s_invalid = "abcdef";  
    match split_string_with_regex(&s_invalid) {  
        Ok((_, _)) => unreachable!(), // 这个分支不应该被执行到  
        Err(e) => {  
            println!("Error for invalid input: {}", e);  
        }  
    }  
}