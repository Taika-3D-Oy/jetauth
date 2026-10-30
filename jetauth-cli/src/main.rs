#[tokio::main]
async fn main() {
    if let Err(error) = jetauth_cli::run().await {
        eprintln!("error: {error}");
        std::process::exit(error.exit_code());
    }
}
