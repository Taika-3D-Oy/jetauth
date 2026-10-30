use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn response(status: u16, value: Value) -> String {
    let body = value.to_string();
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn server<F>(requests: usize, handler: F) -> (String, thread::JoinHandle<()>)
where
    F: Fn(Request) -> String + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut handled = 0;
        while handled < requests && Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    let request = read_request(&stream);
                    let response = handler(request);
                    let mut stream = stream;
                    stream.write_all(response.as_bytes()).unwrap();
                    handled += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("mock server failed: {error}"),
            }
        }
        assert_eq!(handled, requests, "mock server request count");
    });
    (issuer, handle)
}

fn read_request(stream: &TcpStream) -> Request {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap().to_string();
    let path = parts.next().unwrap().to_string();
    let mut headers = Vec::new();
    let mut content_length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap();
        }
        headers.push((name.to_string(), value));
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).unwrap();
    Request {
        method,
        path,
        headers,
        body: String::from_utf8(body).unwrap(),
    }
}

fn command(config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_jetauth"));
    command
        .env("JETAUTH_CONFIG_DIR", config)
        .env_remove("JETAUTH_ACCESS_TOKEN")
        .env_remove("JETAUTH_ISSUER")
        .env_remove("JETAUTH_PROFILE");
    command
}

fn jwt() -> String {
    let claims = URL_SAFE_NO_PAD.encode(
        br#"{"sub":"user_admin","email":"admin@example.com","name":"Admin","role":"superadmin"}"#,
    );
    format!("e30.{claims}.signature")
}

#[test]
fn device_login_refresh_management_token_and_logout() {
    let config = tempfile::tempdir().unwrap();
    let id_token = jwt();
    let token_calls = Arc::new(AtomicUsize::new(0));
    let calls = token_calls.clone();
    let (issuer, server) = server(7, move |request| {
        let issuer = issuer_for_request(&request);
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/.well-known/openid-configuration") => response(
                200,
                json!({
                    "issuer": issuer,
                    "token_endpoint": format!("{issuer}/token"),
                    "device_authorization_endpoint": format!("{issuer}/device_authorization")
                }),
            ),
            ("POST", "/device_authorization") => {
                assert!(request.body.contains("client_id=lid-admin"));
                assert!(request.body.contains("offline_access"));
                response(
                    200,
                    json!({
                        "device_code": "device-secret",
                        "user_code": "ABCD-EFGH",
                        "verification_uri": format!("{issuer}/device"),
                        "verification_uri_complete": format!("{issuer}/device?user_code=ABCD-EFGH"),
                        "expires_in": 60,
                        "interval": 1
                    }),
                )
            }
            ("POST", "/token") => {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    assert!(request.body.contains("device_code=device-secret"));
                    response(400, json!({ "error": "authorization_pending" }))
                } else if request.body.contains("grant_type=refresh_token") {
                    assert!(request.body.contains("refresh_token=old-refresh"));
                    response(
                        200,
                        json!({
                            "access_token": "new-access",
                            "refresh_token": "new-refresh",
                            "expires_in": 3600,
                            "scope": "openid email profile offline_access"
                        }),
                    )
                } else {
                    response(
                        200,
                        json!({
                            "access_token": "old-access",
                            "refresh_token": "old-refresh",
                            "id_token": id_token,
                            "expires_in": 0,
                            "scope": "openid email profile offline_access"
                        }),
                    )
                }
            }
            ("GET", "/api/clients") => {
                assert_eq!(request.header("authorization"), Some("Bearer new-access"));
                response(200, json!([{ "client_id": "client_1", "name": "Portal" }]))
            }
            other => panic!("unexpected request: {other:?}"),
        }
    });
    let login = command(config.path())
        .args([
            "login",
            "--issuer",
            &issuer,
            "--no-browser",
            "--credential-store",
            "file",
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    assert!(login.status.success(), "{}", stderr(&login));
    let login_json: Value = serde_json::from_slice(&login.stdout).unwrap();
    assert_eq!(login_json["email"], "admin@example.com");
    assert_eq!(login_json["role"], "superadmin");
    assert_eq!(login_json["credential_store"], "file");

    let clients = command(config.path())
        .args(["clients", "list", "--output", "json"])
        .output()
        .unwrap();
    assert!(clients.status.success(), "{}", stderr(&clients));
    let clients_json: Value = serde_json::from_slice(&clients.stdout).unwrap();
    assert_eq!(clients_json[0]["client_id"], "client_1");
    server.join().unwrap();

    let token = command(config.path()).arg("token").output().unwrap();
    assert!(token.status.success(), "{}", stderr(&token));
    assert_eq!(
        String::from_utf8(token.stdout).unwrap().trim(),
        "new-access"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::metadata(config.path().join("credentials/default.json"))
            .unwrap()
            .permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    let logout = command(config.path())
        .args(["logout", "--output", "json"])
        .output()
        .unwrap();
    assert!(logout.status.success(), "{}", stderr(&logout));
    assert!(!config.path().join("credentials/default.json").exists());
}

#[test]
fn environment_token_supports_raw_api_without_a_profile() {
    let config = tempfile::tempdir().unwrap();
    let (issuer, server) = server(1, |request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/tenants");
        assert_eq!(request.header("authorization"), Some("Bearer ci-token"));
        assert_eq!(request.body, r#"{"name":"acme"}"#);
        response(201, json!({ "id": "tenant_1", "name": "acme" }))
    });

    let mut child = command(config.path())
        .env("JETAUTH_ACCESS_TOKEN", "ci-token")
        .args([
            "api",
            "POST",
            "/api/tenants",
            "--issuer",
            &issuer,
            "--input",
            "-",
            "--output",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"name":"acme"}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["id"], "tenant_1");
    server.join().unwrap();
}

#[test]
fn destructive_commands_require_confirmation() {
    let config = tempfile::tempdir().unwrap();
    let output = command(config.path())
        .args(["clients", "delete", "client_1", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--yes"));
}

fn issuer_for_request(request: &Request) -> String {
    format!("http://{}", request.header("host").unwrap())
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
