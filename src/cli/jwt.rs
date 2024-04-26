use regex::Regex; 
use clap::Parser;
use enum_dispatch::enum_dispatch;
use anyhow::{Ok, Result};

use crate::{process, CmdExector};

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
    #[arg(long)]
    pub sub: String,
    #[arg(long)]
    pub aud: String,
}

fn parse_exp(exp_ex: String) -> Result<String> {
    let reg = Regex::new(r"^(\d+)([a-zA-Z])$").unwrap();
    if !reg.is_match(&exp_ex) {
        Err(anyhow::anyhow!("input format error"))
    } else {
        let caps = reg.captures(&exp_ex).unwrap();
        let num: i64 = caps[1].parse().unwrap();
        let part = &caps[2];
        let second_count_result = match part {
            "s" => Ok(num),
            "m" => Ok(num * 60),
            "h" => Ok(num * 60 * 60),
            "d" => Ok(num * 60 * 60 * 24),
            _ => Err(anyhow::anyhow!(
                "format error the last char is not [s,m,h,d]"
            )),
        };
        Ok(second_count_result?.to_string())        
    }
}

fn verify_exp_format(exp_ex: &str) -> Result<String> {    
    parse_exp(exp_ex.to_string())   
}

impl CmdExector for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token = process::jwt::jwt_sign(self.sub, self.aud, self.exp.parse::<i64>()?);
        println!("token:{}", token?);
        Ok(())
    }
}

impl CmdExector for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let claim = process::jwt::jwt_verify(self.token, self.sub, self.aud);
        println!("token:{:#?}", claim?);
        Ok(())
    }
}
