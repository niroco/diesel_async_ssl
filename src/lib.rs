use diesel_async::pooled_connection::bb8;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use futures_util::FutureExt;
use futures_util::TryFutureExt;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Diesel: {0}")]
    Db(#[from] diesel::result::Error),

    #[error("Database pool: {0}")]
    Pool(#[from] diesel_async::pooled_connection::PoolError),

    #[error("Database connection: {0}")]
    Connection(#[from] bb8::RunError),
}

pub struct Pool {
    pool: bb8::Pool<diesel_async::AsyncPgConnection>,
}

impl Pool {
    pub fn no_connections(&self) -> u32 {
        self.pool.state().connections
    }
}

pub async fn connect(url: &str) -> Result<Pool, Error> {
    //let manager = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(url);
    let manager = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new_with_setup(
        url,
        |url| {
            println!("URL: {url}");
            let config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            let tls = tokio_postgres_rustls::MakeRustlsConnect::new(config);

            // En error for mycket
            let fut = tokio_postgres::connect(url, tls).map_ok(|(client, conn)| {
                let client = AsyncPgConnection::try_from(client);

                client
            });

            Box::pin(fut)
        },
    );

    let pool = bb8::Pool::builder().build(manager).await?;

    {
        let _conn = pool.get().await?;
    }

    Ok(Pool { pool })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn establish_connection() {
        let db_url = std::env::var("DATABASE_URL").expect("DB url must be set");
        let pool = super::connect(&db_url).await.expect("connecting");

        assert_eq!(pool.no_connections(), 1);

        //let config = rustls::ClientConfig::builder()
        //    .with_safe_defaults()
        //    .with_root_certificates(rustls::RootCertStore::empty())
        //    .with_no_client_auth();
        //let tls = tokio_postgres_rustls::MakeRustlsConnect::new(config);
        //let connect_fut =
        // tokio_postgres::connect("sslmode=require host=localhost user=postgres", tls);
    }
}
