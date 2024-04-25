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
