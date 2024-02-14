use anyhow::Result;
use diesel_async::pooled_connection::{bb8::Pool, AsyncDieselConnectionManager, ManagerConfig};
use diesel_async_ssl::SslManager;

#[tokio::main]
async fn main() -> Result<()> {
    let cert = include_str!("../TEST_CERT.pem");

    let url = std::env::var("DATABASE_URL").expect("env var DATABASE_URL");

    SslManager::default()
        .add_root_pem_cert(cert)
        .expect("adding PEM cert")
        .try_init()
        .expect("Failed to initialize SSL certs");

    let mut config = ManagerConfig::default();
    config.custom_setup = Box::new(diesel_async_ssl::setup_callback);

    let config = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new_with_config(
        url, config,
    );

    let pool = Pool::builder().build(config).await?;

    let _conn = pool.get().await?;

    println!("connected");

    Ok(())
}
