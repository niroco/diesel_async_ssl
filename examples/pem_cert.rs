use anyhow::Result;
use diesel_async::pooled_connection::{bb8::Pool, AsyncDieselConnectionManager};
use diesel_async_ssl::SslManager;

#[tokio::main]
async fn main() -> Result<()> {
    let cert = include_str!("../TEST_CERT.pem");

    let url = std::env::var("DATABASE_URL").expect("env var DATABASE_URL missing");
    let mut ssl_manager = SslManager::default();
    ssl_manager.add_root_pem_cert(cert)?;

    let config = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new_with_setup(
        url,
        ssl_manager.into_setup(),
    );

    let pool = Pool::builder().build(config).await?;

    let mut _conn = pool.get().await?;

    Ok(())
}
