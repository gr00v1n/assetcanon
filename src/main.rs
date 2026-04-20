use std::process::ExitCode;

mod cli;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    cli::run().await
}
