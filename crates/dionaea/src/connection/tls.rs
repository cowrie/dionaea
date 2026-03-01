// ABOUTME: TLS listener, self-signed cert generation, and SSL context setup.
// ABOUTME: Wraps TCP accept with TLS handshake, reuses generic handle_connection for I/O.

use std::net::SocketAddr;
use std::sync::Arc;

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509Builder, X509NameBuilder};
use pyo3::prelude::*;
use tokio::net::TcpListener;
use tokio::time::{self, Duration};

use crate::connection::limits::ConnectionLimits;
use crate::connection::tcp::{
    cleanup_connection, get_fd_soft_limit, handle_connection, RejectConfig,
    SilentConnectionTracker,
};
use crate::connection::{ConnectionRegistry, ConnectionState, ConnectionType, Transport};
use crate::python::connection::factory_create;

/// Certificate subject fields for self-signed cert generation.
#[derive(Debug, Clone)]
pub struct CertSubject {
    /// Country code (e.g. "US").
    pub country: String,
    /// Common name (e.g. "localhost").
    pub common_name: String,
    /// Organization (e.g. "Server").
    pub organization: String,
    /// Organizational unit (e.g. "IT").
    pub organizational_unit: String,
}

impl Default for CertSubject {
    fn default() -> Self {
        CertSubject {
            country: "US".to_string(),
            common_name: "localhost".to_string(),
            organization: "Server".to_string(),
            organizational_unit: "IT".to_string(),
        }
    }
}

/// TLS configuration for a listener.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// RSA key size in bits.
    pub key_bits: u32,
    /// Certificate subject fields.
    pub subject: CertSubject,
    /// Optional cipher list (OpenSSL format). None = OpenSSL defaults.
    pub cipher_list: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            key_bits: 2048,
            subject: CertSubject::default(),
            cipher_list: None,
        }
    }
}

/// Generate an RSA keypair.
fn generate_rsa_keypair(bits: u32) -> Result<PKey<Private>, openssl::error::ErrorStack> {
    let rsa = openssl::rsa::Rsa::generate(bits)?;
    PKey::from_rsa(rsa)
}

/// Generate a self-signed X509 certificate for honeypot use.
///
/// Matches the C dionaea `mkcert()`: RSA key, 365-day validity, SHA256 signature,
/// configurable subject fields from config.
pub fn generate_self_signed_cert(
    config: &TlsConfig,
) -> Result<(PKey<Private>, openssl::x509::X509), openssl::error::ErrorStack> {
    let pkey = generate_rsa_keypair(config.key_bits)?;

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?; // X509 v3

    // Serial number: current unix timestamp
    let serial = {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let bn = BigNum::from_dec_str(&ts.to_string())?;
        bn.to_asn1_integer()?
    };
    builder.set_serial_number(&serial)?;

    // Validity: now → +365 days
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Subject name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, &config.subject.country)?;
    name_builder.append_entry_by_nid(Nid::COMMONNAME, &config.subject.common_name)?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &config.subject.organization)?;
    name_builder.append_entry_by_nid(
        Nid::ORGANIZATIONALUNITNAME,
        &config.subject.organizational_unit,
    )?;
    let name = name_builder.build();
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?; // self-signed

    builder.set_pubkey(&pkey)?;

    // Extensions
    let ctx = builder.x509v3_context(None, None);
    let san = SubjectAlternativeName::new()
        .dns(&config.subject.common_name)
        .build(&ctx)?;
    builder.append_extension(san)?;

    // Sign with SHA256
    builder.sign(&pkey, MessageDigest::sha256())?;

    Ok((pkey, builder.build()))
}

/// Build an SSL acceptor for a TLS listener.
///
/// Uses SSLv23 method (negotiates highest compatible version) and auto DH params,
/// matching the C dionaea behavior. Optionally sets cipher list for honeypot
/// weak-cipher support.
pub fn build_ssl_acceptor(
    pkey: &PKey<Private>,
    cert: &openssl::x509::X509,
    cipher_list: Option<&str>,
) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    builder.set_private_key(pkey)?;
    builder.set_certificate(cert)?;
    builder.set_verify(SslVerifyMode::NONE); // honeypot: don't require client certs

    if let Some(ciphers) = cipher_list {
        builder.set_cipher_list(ciphers)?;
    }

    Ok(builder.build())
}

/// Handle for a running TLS listener.
pub struct TlsListenerHandle {
    /// Abort handle for the accept loop task.
    abort: tokio::task::AbortHandle,
    /// The address the listener is bound to.
    pub addr: SocketAddr,
}

impl TlsListenerHandle {
    /// Stop the listener.
    pub fn stop(&self) {
        self.abort.abort();
    }
}

/// Start a TLS listener on the given address.
pub async fn tls_listen(
    addr: SocketAddr,
    registry: Arc<ConnectionRegistry>,
    limits: Arc<ConnectionLimits>,
    protocol_factory: Py<PyAny>,
    recv_buffer_size: usize,
    reject_config: RejectConfig,
    acceptor: SslAcceptor,
    handshake_timeout: Duration,
) -> std::io::Result<TlsListenerHandle> {
    let listener = TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr()?;
    tracing::info!(%bound_addr, "TLS listener bound");

    let silent_tracker = Arc::new(SilentConnectionTracker::new(reject_config.silence_cap));
    let acceptor = Arc::new(acceptor);

    let task = tokio::spawn(tls_accept_loop(
        listener,
        registry,
        limits,
        protocol_factory,
        recv_buffer_size,
        reject_config,
        silent_tracker,
        acceptor,
        handshake_timeout,
    ));

    Ok(TlsListenerHandle {
        abort: task.abort_handle(),
        addr: bound_addr,
    })
}

/// Accept loop for TLS connections.
///
/// TCP accept → limit check → TLS handshake (with timeout) → handler I/O loop.
async fn tls_accept_loop(
    listener: TcpListener,
    registry: Arc<ConnectionRegistry>,
    limits: Arc<ConnectionLimits>,
    protocol_factory: Py<PyAny>,
    recv_buffer_size: usize,
    reject_config: RejectConfig,
    silent_tracker: Arc<SilentConnectionTracker>,
    acceptor: Arc<SslAcceptor>,
    handshake_timeout: Duration,
) {
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(err = %e, "TLS accept failed");
                continue;
            }
        };

        let peer_ip = peer_addr.ip();
        let local_addr = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

        // Check limits
        let fd_count = registry.len() as u64;
        let fd_soft_limit = get_fd_soft_limit();

        if let Err(reason) =
            limits.check(peer_ip, registry.len() as u32, fd_count, fd_soft_limit)
        {
            tracing::debug!(%peer_addr, %reason, "rejecting TLS connection");
            crate::connection::tcp::reject_connection(stream, &reject_config, &silent_tracker);
            continue;
        }

        // TLS handshake with timeout
        let ssl = match openssl::ssl::Ssl::new(acceptor.context()) {
            Ok(ssl) => ssl,
            Err(e) => {
                tracing::warn!(err = %e, "SSL object creation failed");
                continue;
            }
        };

        let tls_stream = match tokio_openssl::SslStream::new(ssl, stream) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(err = %e, "SslStream creation failed");
                continue;
            }
        };

        let acceptor_clone = acceptor.clone();
        let reg = registry.clone();
        let lim = limits.clone();
        let hs_timeout = handshake_timeout;

        // Clone factory (atomic incref, needs GIL)
        let factory_clone = Python::attach(|py| protocol_factory.clone_ref(py));

        tokio::spawn(async move {
            // Perform TLS handshake with timeout
            let mut tls_stream = tls_stream;
            let handshake_result = time::timeout(hs_timeout, async {
                // Pin required for accept
                let pinned = std::pin::Pin::new(&mut tls_stream);
                pinned.accept().await
            })
            .await;

            match handshake_result {
                Ok(Ok(())) => {
                    // Handshake succeeded
                    tracing::debug!(%peer_addr, "TLS handshake completed");
                }
                Ok(Err(e)) => {
                    tracing::debug!(%peer_addr, err = %e, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer_addr, "TLS handshake timed out");
                    return;
                }
            }

            // Register connection (after handshake succeeds)
            let (id, tx, rx) = reg.register(Transport::Tls, ConnectionType::Accept);
            lim.increment(peer_ip);

            if let Some(mut meta) = reg.get_mut(id) {
                meta.local = crate::node_info::NodeInfo::from_socket_addr(local_addr);
                meta.remote = crate::node_info::NodeInfo::from_socket_addr(peer_addr);
                meta.state = ConnectionState::Established;
            }

            tracing::debug!(connection_id = %id, %peer_addr, "accepted TLS connection");

            let _ = acceptor_clone; // keep alive
            let reg_for_factory = reg.clone();
            let lim_for_factory = lim.clone();
            let handler_tx = tx.clone();

            let child_result = tokio::task::spawn_blocking(move || {
                Python::attach(|py| {
                    let parent = factory_clone.bind(py);
                    factory_create(
                        py,
                        &parent,
                        id,
                        handler_tx,
                        "tls",
                        Some(reg_for_factory),
                        Some(lim_for_factory),
                        recv_buffer_size,
                    )
                })
            })
            .await;

            let handler = match child_result {
                Ok(Ok(h)) => h,
                Ok(Err(e)) => {
                    tracing::error!(connection_id = %id, err = %e, "factory_create failed");
                    cleanup_connection(&reg, &lim, id, peer_ip);
                    return;
                }
                Err(e) => {
                    tracing::error!(connection_id = %id, err = %e, "factory panicked");
                    cleanup_connection(&reg, &lim, id, peer_ip);
                    return;
                }
            };

            // Run the standard I/O handler loop over the TLS stream
            handle_connection(tls_stream, handler, id, rx, reg.clone(), recv_buffer_size).await;
            cleanup_connection(&reg, &lim, id, peer_ip);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnectionId;
    use crate::python::connection::PyConnection;
    use pyo3::types::PyModule;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn register_test_module(py: Python<'_>, name: &str) {
        let module = PyModule::new(py, name).expect("module creation");
        module
            .add_class::<PyConnection>()
            .expect("add PyConnection");
        py.import(c"sys")
            .expect("import sys")
            .getattr("modules")
            .expect("get modules")
            .set_item(name, module)
            .expect("set module");
    }

    fn create_echo_factory(py: Python<'_>, module_name: &str) -> Py<PyAny> {
        register_test_module(py, module_name);
        let code = format!(
            "
from {module_name} import PyConnection
class TlsEchoProtocol(PyConnection):
    def __init__(self, proto=None):
        super().__init__(proto)
    def handle_established(self):
        pass
    def handle_io_in(self, data):
        self.send(data)
        return len(data)
    def handle_disconnect(self):
        return False
factory = TlsEchoProtocol('tls')
"
        );
        let c_code = std::ffi::CString::new(code).expect("CString");
        py.run(c_code.as_c_str(), None, None).expect("define echo");
        let factory = py.eval(c"factory", None, None).expect("factory");
        {
            let mut c = factory
                .cast::<PyConnection>()
                .expect("cast")
                .borrow_mut();
            c.id = Some(ConnectionId(0));
        }
        factory.unbind()
    }

    #[test]
    fn test_self_signed_cert_generation() {
        let config = TlsConfig::default();
        let (pkey, cert) = generate_self_signed_cert(&config).expect("cert generation");

        // Verify key size
        assert_eq!(pkey.bits(), 2048);

        // Verify subject
        let subject = cert.subject_name();
        let cn = subject
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .expect("CN");
        assert_eq!(
            cn.data().as_utf8().expect("utf8").to_string(),
            "localhost"
        );

        let o = subject
            .entries_by_nid(Nid::ORGANIZATIONNAME)
            .next()
            .expect("O");
        assert_eq!(o.data().as_utf8().expect("utf8").to_string(), "Server");

        // Verify it's self-signed
        assert!(cert.verify(&pkey).expect("verify"));
    }

    #[test]
    fn test_ssl_acceptor_builds() {
        let config = TlsConfig::default();
        let (pkey, cert) = generate_self_signed_cert(&config).expect("cert");
        let _acceptor =
            build_ssl_acceptor(&pkey, &cert, None).expect("acceptor");
    }

    #[test]
    fn test_tls_echo_roundtrip() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let reg = Arc::new(ConnectionRegistry::new());
            let lim = Arc::new(ConnectionLimits::new(50, 10_000, 70));
            let factory = Python::attach(|py| create_echo_factory(py, "tls_echo_t"));

            // Generate cert + acceptor
            let tls_config = TlsConfig::default();
            let (pkey, cert) =
                generate_self_signed_cert(&tls_config).expect("cert");
            let acceptor =
                build_ssl_acceptor(&pkey, &cert, None).expect("acceptor");

            let handle = tls_listen(
                "127.0.0.1:0".parse().expect("addr"),
                reg.clone(),
                lim.clone(),
                factory,
                65536,
                RejectConfig::default(),
                acceptor,
                Duration::from_secs(10),
            )
            .await
            .expect("tls_listen");

            time::sleep(Duration::from_millis(50)).await;

            // Connect with a TLS client
            let tcp_stream =
                tokio::net::TcpStream::connect(handle.addr).await.expect("tcp connect");

            let mut connector_builder =
                openssl::ssl::SslConnector::builder(SslMethod::tls()).expect("connector");
            connector_builder.set_verify(SslVerifyMode::NONE);
            let connector = connector_builder.build();

            let ssl = connector
                .configure()
                .expect("configure")
                .into_ssl("localhost")
                .expect("ssl");
            let mut tls_client =
                tokio_openssl::SslStream::new(ssl, tcp_stream).expect("ssl stream");

            let pinned = std::pin::Pin::new(&mut tls_client);
            pinned.connect().await.expect("tls connect");

            time::sleep(Duration::from_millis(100)).await;

            // Send data
            tls_client.write_all(b"hello tls dionaea").await.expect("write");

            // Read echo
            let mut resp = vec![0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(2), tls_client.read(&mut resp))
                .await
                .expect("timeout")
                .expect("read");
            assert_eq!(&resp[..n], b"hello tls dionaea");

            // Verify connection is registered
            assert!(reg.len() >= 1);

            drop(tls_client);
            time::sleep(Duration::from_millis(200)).await;
            handle.stop();
        });
    }
}
