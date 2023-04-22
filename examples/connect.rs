use anyhow::{Context, Result};
use diesel_async::pooled_connection::{bb8::Pool, AsyncDieselConnectionManager};
use diesel_async_ssl::SslManager;
use rustls::Certificate;

#[tokio::main]
async fn main() -> Result<()> {
    let bs = include_bytes!("../TEST_CERT.der");

    let url = std::env::var("DATABASE_URL").expect("env var DATABASE_URL missing");
    let mut ssl_manager = SslManager::default();
    ssl_manager.add_root_cert(Certificate(bs.iter().map(|b| *b).collect()));

    let config = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new_with_setup(
        url,
        ssl_manager.into_setup(),
    );

    let pool = Pool::builder().build(config).await?;

    Ok(())
}
