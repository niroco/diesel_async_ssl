use diesel::ConnectionResult;
use diesel_async::AsyncPgConnection;
use futures::{future, FutureExt, TryFutureExt};
use tracing::debug;
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("no PEM encoded data found in provided source")]
    Missing,

    #[error("reading PEM cert: {0}")]
    Io(std::io::Error),

    #[error("Expected to parse X509-certificate, but found {0}")]
    WrongPEMKind(&'static str),
}

#[derive(Default)]
pub struct SslManager {
    root_certs: Vec<rustls::Certificate>,
}

impl SslManager {
    /// Adds a X509 certificate in PEM format
    pub fn add_root_pem_cert(&mut self, pem_cert: &str) -> Result<(), CertError> {
        let mut bs = pem_cert.as_bytes();

        match rustls_pemfile::read_one(&mut bs) {
            Ok(Some(rustls_pemfile::Item::X509Certificate(bs))) => {
                self.root_certs.push(rustls::Certificate(bs));
                Ok(())
            }
            Ok(Some(rustls_pemfile::Item::RSAKey(_))) => Err(CertError::WrongPEMKind("RSAKey")),
            Ok(Some(rustls_pemfile::Item::PKCS8Key(_))) => Err(CertError::WrongPEMKind("PKCS8Key")),
            Ok(Some(rustls_pemfile::Item::ECKey(_))) => Err(CertError::WrongPEMKind("ECKey")),
            Ok(Some(_)) => Err(CertError::WrongPEMKind("other")),
            Ok(None) => Err(CertError::Missing),

            Err(err) => Err(CertError::Io(err)),
        }
    }

    pub fn add_root_cert(&mut self, cert: rustls::Certificate) {
        self.root_certs.push(cert);
    }

    /// Converts self into setup function that can be used by diesel_async::AsyncDieselConnectionManager.
    /// Panics if any of the root certs contains invalid data.
    pub fn into_setup(
        self,
    ) -> impl Fn(&str) -> future::BoxFuture<'_, ConnectionResult<diesel_async::AsyncPgConnection>>
           + Send
           + Sync
           + 'static {
        let mut cert_store = rustls::RootCertStore::empty();
        let certs = self.root_certs.into_iter().map(|c| c.0).collect::<Vec<_>>();

        let (added, _) = cert_store.add_parsable_certificates(&certs);

        if added != certs.len() {
            // Checked by using add_root_pem_cert
            panic!("One or more certificates are invalid");
        }

        move |url| {
            let config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(cert_store.clone())
                .with_no_client_auth();

            let tls = tokio_postgres_rustls::MakeRustlsConnect::new(config);

            // En error for mycket
            let fut = tokio_postgres::connect(url, tls)
                .map_err(|err| diesel::ConnectionError::BadConnection(err.to_string()))
                .and_then(|(client, conn)| {
                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            warn!("SSL: {err}");
                        } else {
                            debug!("stopping ssl connection");
                        }
                    });

                    AsyncPgConnection::try_from(client)
                });

            fut.boxed()
        }
    }
}

// pub trait WithSsl {
//     fn new_with_ssl(url: &str, ssl_manager: SslManager) -> Self;
// }
//
// impl WithSsl for AsyncDieselConnectionManager<AsyncPgConnection> {
//     fn new_with_ssl(url: &str, ssl_manager: SslManager) -> Self {
//         Self::new_with_setup(url, ssl_manager.setup_fn())
//     }
// }
