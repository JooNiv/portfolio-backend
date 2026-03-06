use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};
extern crate dotenv;

use dotenv::dotenv;
use jsonwebtoken::{self, EncodingKey};
use salvo::http::Method;
use salvo::prelude::*;
use salvo_cors::{AllowHeaders, AllowOrigin, Cors};
use salvo_jwt_auth::{ConstDecoder, QueryFinder};
use salvo_jwt_auth::{HeaderFinder, JwtAuth};
use salvo_rate_limiter::{BasicQuota, FixedGuard, MokaStore, RateLimiter, RemoteIpIssuer};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::sync::OnceLock;
use time::{Duration, OffsetDateTime};
use tracing::{debug, error, info, warn};

static POSTGRES: OnceLock<PgPool> = OnceLock::new();

fn get_secret_key() -> String {
    return std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
}

fn validate_user(username: &str, password: &str) -> bool {
    let expected_username: String = std::env::var("USERNAME").expect("USERNAME must be set");
    let expected_password_hash: String =
        std::env::var("PASSWORD_HASH").expect("PASSWORD_HASH must be set");

    if username != expected_username {
        warn!("Username mismatch: attempted '{}'", username);
        return false;
    }

    let argon2 = Argon2::default();
    let expected_parsed_hash = PasswordHash::new(&expected_password_hash).unwrap();

    match argon2.verify_password(password.as_bytes(), &expected_parsed_hash) {
        Ok(_) => {
            info!("User '{}' authenticated successfully", username);
            true
        }
        Err(_) => {
            warn!("Password verification failed for user '{}'", username);
            false
        }
    }
}

// Helper function to get the PostgreSQL connection pool
#[inline]
pub fn get_postgres() -> &'static PgPool {
    POSTGRES.get().unwrap()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JwtClaims {
    username: String,
    exp: i64,
}

#[derive(Deserialize)]
struct NewNote {
    author: String,
    content: String,
}

#[derive(FromRow, Serialize, Debug)]
struct Note {
    id: i32,
    author: String,
    content: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[handler]
async fn login(req: &mut Request, res: &mut Response) {
    let login_req = match req.parse_json::<LoginRequest>().await {
        Ok(data) => data,
        Err(_) => {
            warn!("Login request parsing failed");
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Text::Plain("Invalid request"));
            return;
        }
    };

    if !validate_user(&login_req.username, &login_req.password) {
        warn!("Invalid credentials for user '{}'", login_req.username);
        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Text::Plain("Invalid credentials"));
        return;
    }

    let exp = OffsetDateTime::now_utc() + Duration::days(1);
    let claims = JwtClaims {
        username: login_req.username.clone(),
        exp: exp.unix_timestamp(),
    };

    let secret = get_secret_key();
    let token = match jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(_) => {
            error!("Token creation failed for user '{}'", login_req.username);
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Text::Plain("Token creation failed"));
            return;
        }
    };

    info!("JWT token issued for user '{}'", login_req.username);
    res.render(Json(LoginResponse { token }));
}

#[handler]
async fn check_token(req: &mut Request, res: &mut Response) {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());
    if let Some(token) = auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
        let secret = get_secret_key();
        let validation = jsonwebtoken::Validation::default();
        match jsonwebtoken::decode::<JwtClaims>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        ) {
            Ok(data) => {
                info!("Token validated for user '{}'", data.claims.username);
                res.render(Json(data.claims));
            }
            Err(e) => {
                warn!("Token validation error: {e}");
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Text::Plain("Invalid token"));
            }
        }
    } else {
        warn!("Missing or invalid Authorization header");
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Text::Plain("Missing or invalid Authorization header"));
    }
}

#[handler]
async fn add_note(req: &mut Request, res: &mut Response) {
    let new_note = req.parse_json::<NewNote>().await;
    match new_note {
        Ok(note) => {
            info!("Adding note by '{}'", note.author);
            let inserted_note = sqlx::query_as::<_, Note>(
                "INSERT INTO notes (author, content) VALUES ($1, $2) RETURNING id, author, content",
            )
            .bind(note.author.clone())
            .bind(note.content.clone())
            .fetch_one(get_postgres())
            .await;

            match inserted_note {
                Ok(note) => {
                    info!("Note added: id={}, author='{}'", note.id, note.author);
                    res.render(Json(note));

                    let notes = sqlx::query_as::<_, Note>("SELECT id, author, content FROM notes")
                        .fetch_all(get_postgres())
                        .await
                        .unwrap_or_else(|e| {
                            error!("Database error: {e}");
                            vec![]
                        });
                    if notes.len() > 5 {
                        let oldest_note_id = notes
                            .iter()
                            .min_by_key(|n| n.id)
                            .map(|n| n.id)
                            .unwrap_or(-1);
                        if oldest_note_id >= 0 {
                            info!("Deleting oldest note id={}", oldest_note_id);
                            let _ = sqlx::query("DELETE FROM notes WHERE id = $1")
                                .bind(oldest_note_id)
                                .execute(get_postgres())
                                .await;
                        }
                    }
                }
                Err(e) => {
                    error!("Database error: {e}");
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                    res.render(Text::Plain("Failed to add note"));
                }
            }
        }
        Err(e) => {
            warn!("Request parsing error: {e}");
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Text::Plain("Invalid request body"));
        }
    }
}

#[handler]
async fn delete_note(req: &mut Request, res: &mut Response) {
    let note_id = req.param::<i32>("id").unwrap_or(-1);
    if note_id < 0 {
        warn!("Invalid note ID for deletion: {}", note_id);
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Text::Plain("Invalid note ID"));
        return;
    }

    let result = sqlx::query("DELETE FROM notes WHERE id = $1")
        .bind(note_id)
        .execute(get_postgres())
        .await;

    match result {
        Ok(done) => {
            if done.rows_affected() == 0 {
                warn!("Note not found for deletion: id={}", note_id);
                res.status_code(StatusCode::NOT_FOUND);
                res.render(Text::Plain("Note not found"));
            } else {
                info!("Note deleted: id={}", note_id);
                res.render(Text::Plain("Note deleted successfully"));
            }
        }
        Err(e) => {
            error!("Database error: {e}");
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Text::Plain("Failed to delete note"));
        }
    }
}

#[handler]
async fn get_notes() -> String {
    let pool = get_postgres();
    let notes = sqlx::query_as::<_, Note>("SELECT id, author, content FROM notes")
        .fetch_all(pool)
        .await
        .unwrap_or_else(|e| {
            error!("Database error: {e}");
            vec![]
        });
    debug!("Fetched {} notes", notes.len());
    serde_json::to_string(&notes).unwrap_or_else(|e| {
        error!("Serialization error: {e}");
        "[]".to_string()
    })
}

#[handler]
async fn empty_handler(_req: &mut Request, _res: &mut Response) {}

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::fmt().init();

    let limiter = RateLimiter::new(
        FixedGuard::default(),
        MokaStore::<std::net::IpAddr, FixedGuard>::default(),
        RemoteIpIssuer,
        BasicQuota::per_minute(100),
    );

    info!("Logging initialized");

    let secret = get_secret_key().to_string();

    let auth_handler: JwtAuth<JwtClaims, _> =
        JwtAuth::new(ConstDecoder::from_secret(secret.as_bytes())).finders(vec![
            Box::new(HeaderFinder::new()),
            Box::new(QueryFinder::new("jwt_token")),
        ]);

    let acceptor = TcpListener::new("0.0.0.0:8698").bind().await;

    let postgres_uri = std::env::var("DATABASE_URL").unwrap();
    info!("Connecting to PostgreSQL at '{}'", postgres_uri);

    let pool = PgPool::connect(&postgres_uri).await.unwrap();
    POSTGRES.set(pool).unwrap();

    let cors = Cors::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(AllowHeaders::any())
        .into_handler();

    let router = Router::new()
        .hoop(cors)
        .hoop(limiter)
        .push(
            Router::with_path("/login")
                .post(login)
                .get(check_token)
                .options(empty_handler),
        )
        .push(
            Router::with_path("/notes")
                .get(get_notes)
                .post(add_note)
                .options(empty_handler)
                .push(
                    Router::with_path("{id}")
                        .hoop(auth_handler)
                        .delete(delete_note)
                        .options(empty_handler),
                ),
        );

    info!("Router structure: {router:?}");
    info!("Server starting on 0.0.0.0:8698");

    Server::new(acceptor).serve(router).await;
}
