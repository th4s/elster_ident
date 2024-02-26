use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::client::conn::http1::Parts;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use notary_server::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse};
use rustls::{Certificate, ClientConfig, RootCertStore};
/// This example shows how to notarize an Elster identity.
///
/// The example uses the notary server from <https://github.com/tlsnotary/tlsn/tree/v0.1.0-alpha.4/notary-server>.
use std::ops::Range;
use std::sync::Arc;
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use headless_chrome::{Browser, protocol::cdp::Network::Cookie};
use qr2term;


// Setting of the application server
const SERVER_DOMAIN: &str = "www.elster.de";

// Setting of the notary server
const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 7047;

// Configuration of notarization
const NOTARY_MAX_TRANSCRIPT_SIZE: usize = 360000;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let browser = Browser::default().unwrap();
    let tab = browser.new_tab().unwrap();

    tab.navigate_to("https://www.elster.de/eportal/login/elstersecure").unwrap();

    let qr_element = tab.wait_for_element("div#elsterSecure-data").unwrap();
    let div_attribute = qr_element.get_attribute_value("data-client-uri").unwrap();
    let qr_code;
    loop {
        match div_attribute {
            Some(value) => {
                qr_code = value;
                break;
            },
            None => {}
        }
    }

    qr2term::print_qr(qr_code).unwrap();
    let logout_button = tab.wait_for_element("button#logoutButton").unwrap();
    let cookies: Vec<Cookie> = tab.get_cookies().unwrap();
    let mut cookie_str = None;
    for cookie in cookies.iter() {
        if cookie.name == "JSESSIONID" {
            cookie_str = Some(format!("{}={}", cookie.name, cookie.value));
        }
    };
    if cookie_str == None {
        logout_button.click().unwrap();
        panic!("Failed to extract cookie from login.");
    }

    let (notary_tls_socket, session_id) =
        request_notarization(NOTARY_HOST, NOTARY_PORT, Some(NOTARY_MAX_TRANSCRIPT_SIZE)).await;

    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(session_id)
        .max_transcript_size(NOTARY_MAX_TRANSCRIPT_SIZE)
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Grab a control handle to the Prover
    let prover_ctrl = prover_fut.control();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build a simple HTTP request
    let request = Request::builder()
        .uri("/eportal/meinestammdaten")
        .method("GET")
        .header("Host", "www.elster.de")
        .header("Accept", "text/html")
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Accept-Encoding", "identity")
        .header("Connection", "keep-alive")
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
        )
        .header("Cookie", cookie_str.unwrap())
        .body(Empty::<Bytes>::new())
        .unwrap();

    println!("Starting an MPC TLS connection with the server");

    debug!("Sending request");
    // Because we don't need to decrypt the response right away, we can defer decryption
    // until after the connection is closed. This will speed up the proving process!
    prover_ctrl.defer_decryption().await.unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    debug!("Request OK");

    // Pretty printing :)
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    let parsed = String::from_utf8_lossy(&payload);
    debug!("{}", parsed);

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Upgrade the prover to an HTTP prover, and start notarization.
    let mut prover = prover.start_notarize();

    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    let commitment_builder = prover.commitment_builder();

    let _sent_id = commitment_builder.commit_sent(&Range {
        start: 0,
        end: sent_len,
    });
    let _recv_id = commitment_builder.commit_recv(&Range {
        start: 0,
        end: recv_len,
    });

    // Finalize, returning the notarized HTTP session
    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");

    // Dump the notarized session to a file
    let mut file = tokio::fs::File::create("elster_session.json")
        .await
        .unwrap();
    file.write_all(
        serde_json::to_string_pretty(&notarized_session.session_proof())
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.data().build_substrings_proof();

    let sent_len = notarized_session.data().sent_transcript().data().len();
    let recv_len = notarized_session.data().recv_transcript().data().len();

    proof_builder
        .reveal_sent(
            &Range {
                start: 0,
                end: sent_len,
            },
            CommitmentKind::Blake3,
        )
        .unwrap();

    proof_builder
        .reveal_recv(
            &Range {
                start: 0,
                end: recv_len,
            },
            CommitmentKind::Blake3,
        )
        .unwrap();

    // Build the proof
    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    // Dump the proof to a file.
    let mut file = tokio::fs::File::create("elster_proof.json").await.unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    logout_button.click().unwrap();
}

/// Requests notarization from the Notary server.
pub async fn request_notarization(
    host: &str,
    port: u16,
    max_transcript_size: Option<usize>,
) -> (tokio_rustls::client::TlsStream<TcpStream>, String) {
    // Connect to the Notary via TLS-TCP
    let pem_file = std::str::from_utf8(include_bytes!("../../fixture/tls/rootCA.crt")).unwrap();
    let mut reader = std::io::BufReader::new(pem_file.as_bytes());
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let certificate = certificates.remove(0);

    let mut root_store = RootCertStore::empty();
    root_store.add(&certificate).unwrap();

    let client_notary_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let notary_connector = TlsConnector::from(Arc::new(client_notary_config));

    let notary_socket = tokio::net::TcpStream::connect((host, port)).await.unwrap();

    let notary_tls_socket = notary_connector
        // Require the domain name of notary server to be the same as that in the server cert
        .connect("tlsnotaryserver.io".try_into().unwrap(), notary_socket)
        .await
        .unwrap();

    // Attach the hyper HTTP client to the notary TLS connection to send request to the /session endpoint to configure notarization and obtain session id
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(notary_tls_socket))
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to configure notarization
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: ClientType::Tcp,
        max_transcript_size,
    })
    .unwrap();

    let request = Request::builder()
        .uri(format!("https://{host}:{port}/session"))
        .method("POST")
        .header("Host", host)
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Either::Left(Full::new(Bytes::from(payload))))
        .unwrap();

    debug!("Sending configuration request");

    let configuration_response = request_sender.send_request(request).await.unwrap();

    debug!("Sent configuration request");

    assert!(configuration_response.status() == StatusCode::OK);

    debug!("Response OK");

    // Pretty printing :)
    let payload = configuration_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    debug!("Notarization response: {:?}", notarization_response,);

    // Send notarization request via HTTP, where the underlying TCP connection will be extracted later
    let request = Request::builder()
        // Need to specify the session_id so that notary server knows the right configuration to use
        // as the configuration is set in the previous HTTP call
        .uri(format!(
            "https://{host}:{port}/notarize?sessionId={}",
            notarization_response.session_id.clone()
        ))
        .method("GET")
        .header("Host", host)
        .header("Connection", "Upgrade")
        // Need to specify this upgrade header for server to extract tcp connection later
        .header("Upgrade", "TCP")
        .body(Either::Right(Empty::<Bytes>::new()))
        .unwrap();

    debug!("Sending notarization request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent notarization request");

    assert!(response.status() == StatusCode::SWITCHING_PROTOCOLS);

    debug!("Switched protocol OK");

    // Claim back the TLS socket after HTTP exchange is done
    let Parts {
        io: notary_tls_socket,
        ..
    } = connection_task.await.unwrap().unwrap();

    (
        notary_tls_socket.into_inner(),
        notarization_response.session_id,
    )
}
