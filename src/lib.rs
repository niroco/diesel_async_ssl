use std::pin::Pin;
use std::sync::OnceLock;

use diesel::ConnectionResult;
use diesel_async::AsyncPgConnection;
use futures_util::Future;
use rustls::{pki_types::CertificateDer, RootCertStore};
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

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Default)]
pub struct SslManager {
    root_certs: Vec<CertificateDer<'static>>,
}

static CERT_STORE: OnceLock<RootCertStore> = OnceLock::new();

impl SslManager {
    /// Adds a X509 certificate in PEM format
    pub fn add_root_pem_cert(mut self, pem_cert: &str) -> Result<Self, CertError> {
        let mut bs = pem_cert.as_bytes();

        match rustls_pemfile::read_one(&mut bs) {
            Ok(Some(rustls_pemfile::Item::X509Certificate(cert))) => {
                self.root_certs.push(cert);
                Ok(self)
            }
            Ok(Some(rustls_pemfile::Item::Pkcs1Key(_))) => Err(CertError::WrongPEMKind("RSAKey")),
            Ok(Some(rustls_pemfile::Item::Pkcs8Key(_))) => Err(CertError::WrongPEMKind("PKCS8Key")),
            Ok(Some(rustls_pemfile::Item::Sec1Key(_))) => Err(CertError::WrongPEMKind("ECKey")),
            Ok(Some(rustls_pemfile::Item::Crl(_))) => Err(CertError::WrongPEMKind("Crl")),
            Ok(Some(rustls_pemfile::Item::Csr(_))) => Err(CertError::WrongPEMKind("Csr")),
            Ok(Some(_)) => Err(CertError::WrongPEMKind("other")),
            Ok(None) => Err(CertError::Missing),

            Err(err) => Err(CertError::Io(err)),
        }
    }

    pub fn try_init(self) -> Result<(), RootCertStore> {
        let mut cert_store = RootCertStore::empty();
        let (added, ignored) = cert_store.add_parsable_certificates(self.root_certs);

        if added == 0 {
            warn!("No certificates were added");
        } else if 0 < ignored {
            warn!("{ignored} certificates were ignored");
        }

        CERT_STORE.set(cert_store)
    }
}

pub fn setup_callback(url: &str) -> BoxFuture<'_, ConnectionResult<AsyncPgConnection>> {
    let fut = async {
        let certs = CERT_STORE.get().ok_or_else(|| {
            diesel::ConnectionError::BadConnection("global cert store not initialized".into())
        })?;

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(certs.clone())
            .with_no_client_auth();

        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(config);

        let (client, conn) = tokio_postgres::connect(url, tls)
            .await
            .map_err(|err| diesel::ConnectionError::BadConnection(err.to_string()))?;

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                warn!("SSL: {err}");
            } else {
                debug!("stopping ssl connection");
            }
        });

        AsyncPgConnection::try_from(client).await
    };

    Box::pin(fut)
}
