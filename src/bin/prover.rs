use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::client::conn::http1::Parts;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use notary_server::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse};
use rustls::{Certificate, ClientConfig, RootCertStore};
use tokio::time::sleep;
/// This example shows how to notarize an Elster identity.
///
/// The example uses the notary server from <https://github.com/tlsnotary/tlsn/tree/v0.1.0-alpha.4/notary-server>.
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use headless_chrome::{Browser, protocol::cdp::Network::Cookie, LaunchOptions};
use headless_chrome::browser::default_executable;
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
    let launch_options = LaunchOptions::default_builder()
        .path(Some(default_executable().unwrap()))
        .idle_browser_timeout(Duration::from_secs(180))
        .build().unwrap();
    let browser = Browser::new(launch_options).unwrap();
    let tab = browser.new_tab().unwrap();

    let mut navigation_counter = 0;
    let qr_code;

    // Sometimes Elster does not provide a QR code at first try? Try 5 times...
    'navigation: loop {
        println!("Navigating to Elster Secure");
        tab.navigate_to("https://www.elster.de/eportal/login/elstersecure").unwrap();
    
        let qr_element = tab.wait_for_element("div#elsterSecure-data").unwrap();
        println!("Waiting for QR code...");
        let div_attribute = qr_element.get_attribute_value("data-client-uri").unwrap();
        let mut qr_code_search_counter = 0;
        'qr_code: loop {
            match div_attribute {
                Some(value) => {
                    qr_code = value;
                    break 'navigation;
                },
                None => {
                    sleep(Duration::from_millis(100)).await;
                    qr_code_search_counter = qr_code_search_counter + 1;
                    if qr_code_search_counter > 30 {
                        break 'qr_code;
                    }
                }
            }
        }
        navigation_counter = navigation_counter + 1;
        if navigation_counter > 5 {
            println!("Unable to fetch QR code from ElsterSecure. Exiting");
            std::process::exit(-1);
        }
    }

    qr2term::print_qr(qr_code).unwrap();
    let mut wait_counter = 0;
    let logout_button;
    loop {
        // default tab timeout is 20... alternatively change default timeout of tab
        match tab.wait_for_element("button#logoutButton") {
            Ok(value) => {
                logout_button = value;
                break;
            },
            Err(_) => {
                // wait 
                wait_counter = wait_counter + 1;
                println!("Waiting...");
                if wait_counter > 10 {
                    println!("Login timedout");
                    std::process::exit(0);
                }
            }
        }
    }
    let cookies: Vec<Cookie> = tab.get_cookies().unwrap();
    let mut session_cookie = None;
    for cookie in cookies.iter() {
        if cookie.name == "JSESSIONID" {
            session_cookie = Some(format!("{}={}", cookie.name, cookie.value));
        }
    };
    if session_cookie == None {
        let _ = logout_button.click();
        println!("Failed to extract cookie from login.");
        std::process::exit(-1);
    }
    let session_cookie = session_cookie.unwrap();

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
        .header("Cookie", &session_cookie)
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


    let sent_public_ranges = find_excluded(
        prover.sent_transcript().data(),
        &[session_cookie.as_bytes()]);
    let recv_public_ranges = find_identity_fields(
        prover.recv_transcript().data()
    );

    let commitment_builder = prover.commitment_builder();

    // Commit to each range of the public outbound data which we want to disclose
    let sent_commitments: Vec<_> = sent_public_ranges
        .iter()
        .map(|range| commitment_builder.commit_sent(range).unwrap())
        .collect();
    // Commit to each range of the public inbound data which we want to disclose
    let recv_commitments: Vec<_> = recv_public_ranges
        .iter()
        .map(|range| commitment_builder.commit_recv(range).unwrap())
        .collect();

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

    // Reveal all the public ranges
    for commitment_id in sent_commitments {
        proof_builder.reveal_by_id(commitment_id).unwrap();
    }
    for commitment_id in recv_commitments {
        proof_builder.reveal_by_id(commitment_id).unwrap();
    }

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

    let _ = logout_button.click();
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


fn find_excluded(seq: &[u8], private_seq: &[&[u8]]) -> Vec<Range<usize>> {
    let mut private_ranges = Vec::new();
    for s in private_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    public_ranges
}


fn find_identity_fields(seq: &[u8]) -> Vec<Range<usize>> {
    let fields = ["Identifikationsnummer", "Titel", "Vorname", "Nachname", "Geburtsdatum", "Anschrift"];
    let close_div = "</div>".as_bytes();
    let close_symbol = ">".as_bytes();
    
    let mut public_ranges = Vec::new();
    // find start idx
    let start_txt = "Angaben zur Person".as_bytes();

    let mut start_idx = 0;
    for (idx, w) in seq.windows(start_txt.len()).enumerate() {
        if w == start_txt {
            start_idx = idx;
            break;
        }
    }
    for field in fields.iter() {
        let field_bytes = field.as_bytes();
        'outer_id: for (idx, w) in seq.windows(field_bytes.len()).skip(start_idx).enumerate() {
            if w == field_bytes {
                // found field
                public_ranges.push(start_idx + idx..start_idx + idx + w.len());
                
                // now find value
                // skip a </div> now
                let skip_idx = start_idx + idx + w.len() + close_div.len() + 1;
                // a html tag follows < ... > , find where that one closes
                for (j, symb) in seq.windows(1).skip(skip_idx).enumerate() {
                    if symb == close_symbol {
                        // idx+j+1 is start_idx
                        // value ends with an </div>, when that comes the range ends
                        for (k, w2) in seq.windows(close_div.len()).skip(skip_idx).enumerate() {
                            if w2 == close_div {
                                public_ranges.push(skip_idx+j+1..skip_idx+k);
                                break 'outer_id;
                            }
                        }
                    }
                }
            }
        }
    }

    public_ranges
}
