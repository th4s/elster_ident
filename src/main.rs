use std::ops::Range;

/// This example shows how to notarize an Elster identity.
///
/// The example uses the notary server from <https://github.com/tlsnotary/tlsn/tree/v0.1.0-alpha.4/notary-server>.
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

// Some helper functions
mod util;

use util::request_notarization;

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

    let cookie_str = std::env::var("COOKIE").unwrap();
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
        .header("Cookie", cookie_str)
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
}
