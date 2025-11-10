use argon2::{
    Argon2, PasswordHash, PasswordVerifier, password_hash::{PasswordHasher, SaltString, rand_core::OsRng}
};
use axum::{
    Router,
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};
use validator::Validate;
use jsonwebtoken::{encode, EncodingKey, Header};

mod config;

#[derive(Deserialize, Validate)]
struct SignupPayload {
    #[validate(length(min = 1, message = "name cannot be empty "))]
    name: String,

    #[validate(length(min = 3, message = "username must be atleast 3 character long"))]
    username: String,

    #[validate(length(min = 3, message = "password too short"))]
    password: String,

    #[validate(email(message = "invalid email!"))]
    email: String,
}

#[derive(Serialize)]
struct SignupResponse {
    message: &'static str,
    username: String,
}
#[derive(Validate)]
struct SigninPayload {
    #[validate(length(min = 1, message = "username cannot be empty"))]
    username: String,
    #[validate(length(min = 1, message = "password cannot be empty"))]
    password: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

async fn signup(
    State(pool): State<PgPool>,
    Json(payload): Json<SignupPayload>,
) -> impl IntoResponse {
    if let Err(errors) = payload.validate() {
        let error_map = errors
            .field_errors()
            .iter()
            .map(|(field, errs)| {
                let messages: Vec<String> = errs
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(|m| m.to_string()))
                    .collect();
                (field.to_string(), serde_json::json!(messages))
            })
            .collect::<serde_json::Map<_, _>>();

        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "errors": error_map })),
        );
    };

    let salt = SaltString::generate(&mut OsRng);
    println!("salt is: {}", salt.to_string());

    let argon2 = Argon2::default();

    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(value) => value.to_string(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error":"Failed to hash the password"
                })),
            );
        }
    };
    println!("hashed password: {password_hash}");

    let result = sqlx::query!(
        "insert into  users (username, name, email, password) values ($1, $2, $3, $4)",
        payload.username,
        payload.name,
        payload.email,
        password_hash
    )
    .execute(&pool)
    .await;

    use sqlx::Error;
    match result {
        Ok(_) => {
            let response = SignupResponse {
                message: "signup successful",
                username: payload.username,
            };
            (
                StatusCode::OK,
                Json(serde_json::to_value(response).unwrap()),
            )
        }
        Err(Error::Database(db_err)) => {
            if db_err.code().as_deref() == Some("23505") {
                // Unique violation
                let msg = if let Some(constraint) = db_err.constraint() {
                    if constraint.contains("username") {
                        "Username already exists"
                    } else if constraint.contains("email") {
                        "Email already registered"
                    } else {
                        "Duplicate entry"
                    }
                } else {
                    "Duplicate entry"
                };
                (StatusCode::CONFLICT, Json(json!({"error": msg})))
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": db_err.to_string()})),
                )
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn signin(
    State(pool): State<PgPool>,
    Json(payload): Json<SigninPayload>,
) -> impl IntoResponse {
    // Validate payload
    if let Err(errors) = payload.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "errors": errors })),
        );
    }

    // Fetch user from DB
    let user = sqlx::query!(
        "SELECT password FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&pool)
    .await
    .unwrap();

    if let Some(user) = user {
        // Verify password
        let parsed_hash = PasswordHash::new(&user.password).unwrap();
        if Argon2::default()
            .verify_password(payload.password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid credentials" })),
            );
        }

        // Create JWT
        let exp = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::hours(24))
            .unwrap()
            .timestamp() as usize;

        let claims = Claims {
            sub: payload.username.clone(),
            exp,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"your_jwt_secret"),
        )
        .unwrap();

        return (
            StatusCode::OK,
            Json(json!({ "message": "signin successful", "token": token })),
        );
    }

    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "user not found" })),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(config::DATABASE_URL)
        .await?;
    println!("Connected to Postgres!");

    let router = Router::new()
        .route("/", get(|| async { "hello world" }))
        .route("/signup", post(signup))
        .with_state(pool);
    let listener = tokio::net::TcpListener::bind("0.0.0:3000").await.unwrap();
    axum::serve(listener, router).await.unwrap();

    Ok(())
}
