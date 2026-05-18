use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use clap::Parser;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Incoming, server::conn::http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify},
};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, env = "SYNC_BARRIER_HOST", default_value = "0.0.0.0")]
    host: String,
    #[arg(long, env = "SYNC_BARRIER_PORT", default_value_t = 8083)]
    port: u16,
}

#[derive(Debug, Default)]
struct RunState {
    expected: usize,
    ready: HashMap<String, u128>,
    released_at_unix_ms: Option<u128>,
}

#[derive(Debug, Clone, Default)]
struct AppState {
    runs: Arc<Mutex<HashMap<String, RunState>>>,
    notify: Arc<Notify>,
}

#[derive(Debug, Deserialize, Serialize)]
struct StatusBody {
    ok: bool,
    run_id: String,
    participants: usize,
    ready_count: usize,
    released: bool,
    released_at_unix_ms: Option<u128>,
    max_ready_skew_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("response should build")
}

fn status_for(run_id: &str, run: Option<&RunState>, error: Option<String>) -> StatusBody {
    let (participants, ready_count, released_at_unix_ms, max_ready_skew_ms) =
        run.map_or((0, 0, None, None), |run| {
            let skew = if run.ready.len() <= 1 {
                Some(0.0)
            } else {
                let min = run.ready.values().min().copied().unwrap_or_default();
                let max = run.ready.values().max().copied().unwrap_or_default();
                Some((max.saturating_sub(min)) as f64)
            };
            (run.expected, run.ready.len(), run.released_at_unix_ms, skew)
        });
    StatusBody {
        ok: error.is_none(),
        run_id: run_id.to_string(),
        participants,
        ready_count,
        released: released_at_unix_ms.is_some(),
        released_at_unix_ms,
        max_ready_skew_ms,
        error,
    }
}

fn query_value<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    query?.split('&').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        (name == key).then_some(value)
    })
}

fn parse_participants(query: Option<&str>) -> Result<usize, String> {
    let raw = query_value(query, "participants").ok_or("missing participants")?;
    let participants = raw
        .parse::<usize>()
        .map_err(|err| format!("invalid participants: {err}"))?;
    if participants == 0 {
        return Err("participants must be greater than zero".to_string());
    }
    Ok(participants)
}

fn parse_timeout(query: Option<&str>) -> Duration {
    query_value(query, "timeout_ms")
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(120))
}

fn ready_path(path: &str) -> Option<(String, String)> {
    let suffix = path.strip_prefix("/runs/")?;
    let (run_id, participant_id) = suffix.split_once("/ready/")?;
    if run_id.is_empty() || participant_id.is_empty() || participant_id.contains('/') {
        return None;
    }
    Some((run_id.to_string(), participant_id.to_string()))
}

fn action_path(path: &str, action: &str) -> Option<String> {
    let suffix = path.strip_prefix("/runs/")?;
    let run_id = suffix.strip_suffix(action)?;
    (!run_id.is_empty() && !run_id.contains('/')).then(|| run_id.to_string())
}

async fn ready(
    state: AppState,
    run_id: String,
    participant_id: String,
    participants: usize,
) -> Response<Full<Bytes>> {
    let mut runs = state.runs.lock().await;
    let run = runs.entry(run_id.clone()).or_insert_with(|| RunState {
        expected: participants,
        ready: HashMap::new(),
        released_at_unix_ms: None,
    });
    if run.expected != participants {
        return json_response(
            StatusCode::CONFLICT,
            &status_for(
                &run_id,
                Some(run),
                Some("participant count mismatch".to_string()),
            ),
        );
    }
    if run.released_at_unix_ms.is_some() {
        return json_response(
            StatusCode::CONFLICT,
            &status_for(&run_id, Some(run), Some("run already released".to_string())),
        );
    }
    if run.ready.contains_key(&participant_id) {
        return json_response(
            StatusCode::CONFLICT,
            &status_for(
                &run_id,
                Some(run),
                Some("duplicate participant".to_string()),
            ),
        );
    }
    run.ready.insert(participant_id, unix_ms_now());
    let body = status_for(&run_id, Some(run), None);
    drop(runs);
    state.notify.notify_waiters();
    json_response(StatusCode::OK, &body)
}

async fn release(state: AppState, run_id: String, participants: usize) -> Response<Full<Bytes>> {
    let mut runs = state.runs.lock().await;
    let Some(run) = runs.get_mut(&run_id) else {
        return json_response(
            StatusCode::NOT_FOUND,
            &status_for(&run_id, None, Some("unknown run".to_string())),
        );
    };
    if run.expected != participants {
        return json_response(
            StatusCode::CONFLICT,
            &status_for(
                &run_id,
                Some(run),
                Some("participant count mismatch".to_string()),
            ),
        );
    }
    if run.ready.len() != run.expected {
        return json_response(
            StatusCode::CONFLICT,
            &status_for(
                &run_id,
                Some(run),
                Some("not all participants are ready".to_string()),
            ),
        );
    }
    if run.released_at_unix_ms.is_none() {
        run.released_at_unix_ms = Some(unix_ms_now());
    }
    let body = status_for(&run_id, Some(run), None);
    drop(runs);
    state.notify.notify_waiters();
    json_response(StatusCode::OK, &body)
}

async fn status(state: AppState, run_id: String) -> Response<Full<Bytes>> {
    let runs = state.runs.lock().await;
    let run = runs.get(&run_id);
    let code = if run.is_some() {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    json_response(
        code,
        &status_for(
            &run_id,
            run,
            run.is_none().then(|| "unknown run".to_string()),
        ),
    )
}

async fn wait(state: AppState, run_id: String, timeout: Duration) -> Response<Full<Bytes>> {
    let wait_for_release = async {
        loop {
            let notified = state.notify.notified();
            {
                let runs = state.runs.lock().await;
                if runs
                    .get(&run_id)
                    .and_then(|run| run.released_at_unix_ms)
                    .is_some()
                {
                    return;
                }
            }
            notified.await;
        }
    };
    if tokio::time::timeout(timeout, wait_for_release)
        .await
        .is_err()
    {
        let runs = state.runs.lock().await;
        return json_response(
            StatusCode::REQUEST_TIMEOUT,
            &status_for(
                &run_id,
                runs.get(&run_id),
                Some("barrier wait timeout".to_string()),
            ),
        );
    }
    status(state, run_id).await
}

async fn handle(
    req: Request<Incoming>,
    state: AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query();

    let response = if method == Method::GET && path == "/health" {
        json_response(StatusCode::OK, &serde_json::json!({"ok": true}))
    } else if method == Method::POST {
        if let Some((run_id, participant_id)) = ready_path(&path) {
            match parse_participants(query) {
                Ok(participants) => ready(state, run_id, participant_id, participants).await,
                Err(error) => {
                    json_response(StatusCode::BAD_REQUEST, &status_for("", None, Some(error)))
                }
            }
        } else if let Some(run_id) = action_path(&path, "/release") {
            match parse_participants(query) {
                Ok(participants) => release(state, run_id.to_string(), participants).await,
                Err(error) => {
                    json_response(StatusCode::BAD_REQUEST, &status_for("", None, Some(error)))
                }
            }
        } else {
            json_response(
                StatusCode::NOT_FOUND,
                &serde_json::json!({"ok": false, "error": "not found"}),
            )
        }
    } else if method == Method::GET {
        if let Some(run_id) = action_path(&path, "/wait") {
            wait(state, run_id.to_string(), parse_timeout(query)).await
        } else if let Some(run_id) = action_path(&path, "/status") {
            status(state, run_id.to_string()).await
        } else {
            json_response(
                StatusCode::NOT_FOUND,
                &serde_json::json!({"ok": false, "error": "not found"}),
            )
        }
    } else {
        json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &serde_json::json!({"ok": false, "error": "method not allowed"}),
        )
    };
    Ok(response)
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    let state = AppState::default();
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();
        tokio::spawn(async move {
            let executor = TokioExecutor::new();
            let builder = http2::Builder::new(executor);
            let service = hyper::service::service_fn(move |req| {
                let state = state.clone();
                async move { handle(req, state).await }
            });
            if let Err(err) = builder.serve_connection(io, service).await {
                eprintln!("sync-barrier connection error: {err}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body(response: Response<Full<Bytes>>) -> StatusBody {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body should collect")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("status body should decode")
    }

    #[test]
    fn parses_required_participant_count() {
        assert_eq!(parse_participants(Some("participants=3")).unwrap(), 3);
        assert!(parse_participants(None).is_err());
        assert!(parse_participants(Some("participants=0")).is_err());
    }

    #[test]
    fn parses_barrier_paths() {
        assert_eq!(
            ready_path("/runs/run-1/ready/client_1"),
            Some(("run-1".to_string(), "client_1".to_string()))
        );
        assert_eq!(
            action_path("/runs/run-1/release", "/release"),
            Some("run-1".to_string())
        );
        assert!(ready_path("/runs/run-1/ready/client/1").is_none());
    }

    #[tokio::test]
    async fn release_requires_all_participants_ready() {
        let state = AppState::default();
        let ready_response = ready(
            state.clone(),
            "run-1".to_string(),
            "client_1".to_string(),
            2,
        )
        .await;
        assert_eq!(ready_response.status(), StatusCode::OK);

        let partial = release(state.clone(), "run-1".to_string(), 2).await;
        assert_eq!(partial.status(), StatusCode::CONFLICT);
        assert_eq!(body(partial).await.ready_count, 1);

        let second_ready = ready(
            state.clone(),
            "run-1".to_string(),
            "client_2".to_string(),
            2,
        )
        .await;
        assert_eq!(second_ready.status(), StatusCode::OK);

        let released = release(state, "run-1".to_string(), 2).await;
        assert_eq!(released.status(), StatusCode::OK);
        let released = body(released).await;
        assert!(released.released);
        assert_eq!(released.ready_count, 2);
    }

    #[tokio::test]
    async fn wait_returns_immediately_for_already_released_run() {
        let state = AppState::default();
        assert_eq!(
            ready(
                state.clone(),
                "run-1".to_string(),
                "client_1".to_string(),
                1
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            release(state.clone(), "run-1".to_string(), 1)
                .await
                .status(),
            StatusCode::OK
        );

        let response = tokio::time::timeout(
            Duration::from_millis(10),
            wait(state, "run-1".to_string(), Duration::from_secs(120)),
        )
        .await
        .expect("released runs should not wait for another notification");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(body(response).await.released);
    }
}
