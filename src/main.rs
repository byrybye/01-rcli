// rcli csv -i input.csv -o output.json --header -d ','


//写一点注释
//修改一下备注

use clap::Parser;
use rcli::{CmdExector, Opts};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Opts::parse();
    opts.cmd.execute().await?;

    Ok(())
}
