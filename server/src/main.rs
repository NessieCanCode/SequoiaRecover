use actix_web::{web, App, HttpServer, HttpResponse, Responder, HttpRequest};
use sequoiarecover::backup::{run_backup, CompressionType, BackupMode};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::collections::HashMap;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use rand::Rng;
use chrono::{Utc, Duration};
use totp_lite::{totp, Sha1};

#[derive(Clone, Serialize, Deserialize)]
struct User {
    username: String,
    password: String, // stored as plain for simplicity
    roles: Vec<String>,
    totp_secret: Option<String>,
}

#[derive(Default)]
struct AppState {
    users: Mutex<HashMap<String, User>>, // username -> User
    audit: Mutex<Vec<String>>,          // simple audit log strings
    alerts: Mutex<Vec<String>>,         // received security alerts
    jwt_secret: Vec<u8>,
}

#[derive(Deserialize)]
struct RegisterReq {
    username: String,
    password: String,
}

async fn register(data: web::Data<AppState>, req: web::Json<RegisterReq>) -> impl Responder {
    let mut users = data.users.lock().unwrap();
    if users.contains_key(&req.username) {
        return HttpResponse::BadRequest().body("User exists");
    }
    let user = User {
        username: req.username.clone(),
        password: req.password.clone(),
        roles: vec!["user".to_string()],
        totp_secret: None,
    };
    users.insert(req.username.clone(), user);
    data.audit.lock().unwrap().push(format!("registered {}", req.username));
    HttpResponse::Ok().finish()
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
    otp: Option<String>,
}

#[derive(Serialize)]
struct LoginResp {
    token: String,
}

async fn login(data: web::Data<AppState>, req: web::Json<LoginReq>) -> impl Responder {
    let users = data.users.lock().unwrap();
    if let Some(user) = users.get(&req.username) {
        if user.password != req.password {
            return HttpResponse::Unauthorized().finish();
        }
        if let Some(secret) = &user.totp_secret {
            if let Some(code) = &req.otp {
                let code_int: u32 = code.parse().unwrap_or(0);
                let epoch = Utc::now().timestamp() as u64;
                let expected: u32 = totp::<Sha1>(secret.as_bytes(), epoch).parse().unwrap_or(0);
                if code_int != expected {
                    return HttpResponse::Unauthorized().body("Invalid OTP");
                }
            } else {
                return HttpResponse::Unauthorized().body("OTP required");
            }
        }
        let claims = serde_json::json!({
            "sub": user.username,
            "roles": user.roles,
            "exp": (Utc::now() + Duration::hours(1)).timestamp(),
        });
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(&data.jwt_secret)).unwrap();
        data.audit.lock().unwrap().push(format!("login {}", user.username));
        HttpResponse::Ok().json(LoginResp { token })
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

fn verify_token(data: &AppState, token: &str) -> Option<(String, Vec<String>)> {
    let decoded = decode::<serde_json::Value>(token, &DecodingKey::from_secret(&data.jwt_secret), &Validation::default()).ok()?;
    let sub = decoded.claims.get("sub")?.as_str()?.to_string();
    let roles = decoded.claims.get("roles")?.as_array()?.iter().filter_map(|v| v.as_str().map(String::from)).collect();
    Some((sub, roles))
}

async fn list_users(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if let Some((_, roles)) = verify_token(&data, token) {
        if roles.contains(&"admin".to_string()) {
            let users = data.users.lock().unwrap();
            let list: Vec<_> = users.values().cloned().collect();
            return HttpResponse::Ok().json(list);
        }
    }
    HttpResponse::Unauthorized().finish()
}

#[derive(Deserialize)]
struct RoleReq { username: String, role: String }

async fn add_role(data: web::Data<AppState>, req: HttpRequest, payload: web::Json<RoleReq>) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if let Some((_, roles)) = verify_token(&data, token) {
        if roles.contains(&"admin".to_string()) {
            let mut users = data.users.lock().unwrap();
            if let Some(u) = users.get_mut(&payload.username) {
                if !u.roles.contains(&payload.role) {
                    u.roles.push(payload.role.clone());
                    data.audit.lock().unwrap().push(format!("role {} added to {}", payload.role, payload.username));
                    return HttpResponse::Ok().finish();
                }
            }
            return HttpResponse::BadRequest().body("user missing");
        }
    }
    HttpResponse::Unauthorized().finish()
}

async fn audit_log(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if let Some((_, roles)) = verify_token(&data, token) {
        if roles.contains(&"admin".to_string()) {
            let log = data.audit.lock().unwrap();
            return HttpResponse::Ok().json(&*log);
        }
    }
    HttpResponse::Unauthorized().finish()
}

#[derive(Deserialize)]
struct AlertMsg { message: String }

async fn push_alert(data: web::Data<AppState>, msg: web::Json<AlertMsg>) -> impl Responder {
    data.alerts.lock().unwrap().push(msg.message.clone());
    HttpResponse::Ok().finish()
}

#[derive(Deserialize)]
struct BackupReq {
    source: String,
    output: String,
}

async fn start_backup(req: web::Json<BackupReq>) -> impl Responder {
    match run_backup(&req.source, &req.output, CompressionType::Gzip, BackupMode::Full) {
        Ok(_) => HttpResponse::Ok().body("backup complete"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn list_alerts(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if let Some((_, roles)) = verify_token(&data, token) {
        if roles.contains(&"admin".to_string()) {
            let alerts = data.alerts.lock().unwrap();
            return HttpResponse::Ok().json(&*alerts);
        }
    }
    HttpResponse::Unauthorized().finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut rng = rand::thread_rng();
    let secret: [u8; 32] = rng.gen();
    let _ = sequoiarecover::remote::load_providers_from_config();
    let _ = sequoiarecover::remote::load_providers_from_env();
    let data = web::Data::new(AppState { users: Mutex::new(HashMap::new()), audit: Mutex::new(Vec::new()), alerts: Mutex::new(Vec::new()), jwt_secret: secret.to_vec() });
    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/users", web::get().to(list_users))
            .route("/roles", web::post().to(add_role))
            .route("/audit", web::get().to(audit_log))
            .route("/alert", web::post().to(push_alert))
            .route("/backup", web::post().to(start_backup))
            .route("/alerts", web::get().to(list_alerts))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

