use axum::{routing::post, Json, Router, extract::State};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use teloxide::prelude::*;
use teloxide::types::ChatId;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Deserialize, Debug)]
struct AuthNotification {
    username: String,
    ip: String,
    code: String,
    service: String,
    command: Option<String>,
}

struct AppState {
    bot: Bot,
    admin_ids: Vec<i64>,
    ban_list: Mutex<HashMap<String, Instant>>,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let bot_token = std::env::var("TELOXIDE_TOKEN").expect("TELOXIDE_TOKEN must be set");
    let admin_ids_raw = std::env::var("ADMIN_IDS").expect("ADMIN_IDS must be set");
    let admin_ids: Vec<i64> = admin_ids_raw
        .split(',')
        .map(|s| s.trim().parse().expect("Invalid Admin ID"))
        .collect();

    let bot = Bot::new(bot_token);
    let shared_state = Arc::new(AppState {
        bot: bot.clone(),
        admin_ids,
        ban_list: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/notify", post(handle_notify))
        .route("/check_ban", post(handle_check_ban))
        .route("/report_fail", post(handle_report_fail))
        .with_state(shared_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct BanCheck {
    ip: String,
}

async fn handle_check_ban(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<BanCheck>,
) -> (axum::http::StatusCode, &'static str) {
    let mut ban_list = state.ban_list.lock().await;
    if let Some(&expiry) = ban_list.get(&payload.ip) {
        if Instant::now() < expiry {
            return (axum::http::StatusCode::FORBIDDEN, "Banned");
        } else {
            ban_list.remove(&payload.ip);
        }
    }
    (axum::http::StatusCode::OK, "OK")
}

async fn handle_report_fail(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<BanCheck>,
) -> &'static str {
    let mut ban_list = state.ban_list.lock().await;
    ban_list.insert(payload.ip, Instant::now() + Duration::from_secs(15 * 60));
    "Banned"
}

async fn handle_notify(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthNotification>,
) -> (axum::http::StatusCode, &'static str) {
    {
        let mut ban_list = state.ban_list.lock().await;
        if let Some(&expiry) = ban_list.get(&payload.ip) {
            if Instant::now() < expiry {
                return (axum::http::StatusCode::FORBIDDEN, "Banned");
            } else {
                ban_list.remove(&payload.ip);
            }
        }
    }

    tracing::info!("Received notification for user: {}", payload.username);

    let mut message = format!(
        "🚨 *Auth Attempt*\n\n\
        👤 *User:* `{}`\n\
        🌐 *IP:* `{}`\n\
        🛠 *Service:* `{}`\n",
        payload.username.replace('-', "\\-").replace('.', "\\.").replace('_', "\\_"),
        payload.ip.replace('-', "\\-").replace('.', "\\.").replace('_', "\\_"),
        payload.service.replace('-', "\\-").replace('.', "\\.").replace('_', "\\_")
    );

    if let Some(cmd) = payload.command {
        message.push_str(&format!(
            "📝 *Command:* `{}`\n",
            cmd.replace('-', "\\-").replace('.', "\\.").replace('_', "\\_")
        ));
    }

    message.push_str(&format!(
        "🔑 *Verification Code:* `{}`",
        payload.code.replace('-', "\\-").replace('.', "\\.").replace('_', "\\_")
    ));

    for &admin_id in &state.admin_ids {
        let _ = state.bot
            .send_message(ChatId(admin_id), &message)
            .parse_mode(teloxide::types::ParseMode::MarkdownV2)
            .await;
    }

    (axum::http::StatusCode::OK, "OK")
}
