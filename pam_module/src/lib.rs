#[macro_use]
extern crate pamsm;

use pamsm::{PamServiceModule, Pam, PamFlags, PamError, PamLibExt, PamMsgStyle};
use rand::Rng;
use serde::Serialize;
use std::time::Duration;

struct TelegramPam;

#[derive(Serialize)]
struct AuthNotification {
    username: String,
    ip: String,
    code: String,
    service: String,
    command: Option<String>,
}

#[derive(Serialize)]
struct BanCheck {
    ip: String,
}

const BACKEND_URL: &str = "http://localhost:8080";

impl PamServiceModule for TelegramPam {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        let result = std::panic::catch_unwind(|| {
            let client = match reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build() 
            {
                Ok(c) => c,
                Err(_) => return PamError::SERVICE_ERR,
            };

            let ip = pamh.get_rhost().ok().flatten()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".to_string());

            let ban_payload = BanCheck { ip: ip.clone() };
            
            match client.post(format!("{}/check_ban", BACKEND_URL))
                .json(&ban_payload)
                .send() 
            {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::FORBIDDEN {
                        return PamError::AUTH_ERR;
                    }
                }
                Err(_) => {
                    return PamError::SUCCESS;
                }
            }

            let username = pamh.get_user(None).ok().flatten()
                .map(|u| u.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".to_string());

            let service = pamh.get_service().ok().flatten()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".to_string());

            let command = if service == "sudo" {
                pamh.getenv("SUDO_COMMAND").ok().flatten()
                    .map(|c| c.to_string_lossy().into_owned())
            } else {
                None
            };

            let code: String = rand::thread_rng().gen_range(100000..999999).to_string();

            let notification = AuthNotification {
                username, ip: ip.clone(), code: code.clone(), service, command,
            };

            if client.post(format!("{}/notify", BACKEND_URL))
                .json(&notification)
                .send()
                .is_err()
            {
                return PamError::SUCCESS;
            }

            match pamh.conv(Some("Verification Code: "), PamMsgStyle::PROMPT_ECHO_OFF) {
                Ok(Some(user_input)) => {
                    if user_input.to_string_lossy().trim() == code {
                        return PamError::SUCCESS;
                    }
                }
                _ => {}
            }

            let _ = client.post(format!("{}/report_fail", BACKEND_URL))
                .json(&ban_payload)
                .send();

            PamError::AUTH_ERR
        });

        match result {
            Ok(err_code) => err_code,
            Err(_) => PamError::SERVICE_ERR,
        }
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

pam_module!(TelegramPam);
