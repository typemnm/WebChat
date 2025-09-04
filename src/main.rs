use axum::{
    extract::{
        ws::{Message, WebSocket},
        connect_info::ConnectInfo,
        ws::WebSocketUpgrade,
        State, Path, Query,
    },
    http::{header, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use bcrypt::{hash, verify};
use dotenvy::dotenv;
use futures::{sink::SinkExt, stream::StreamExt};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::sync::broadcast;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// --- 모델 및 상태 정의 ---

// JWT 클레임
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // 사용자 이름
    user_id: i32,
    exp: usize,
}

// 사용자 DB 모델
#[derive(Debug, FromRow)]
struct User {
    id: i32,
    username: String,
    password_hash: String,
}

// 인증 요청 페이로드
#[derive(Debug, Deserialize)]
struct AuthPayload {
    username: String,
    password: String,
}

// 채팅방 관리 상태
type ChatRooms = Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>;

// 애플리케이션 공유 상태
#[derive(Clone)]
struct AppState {
    db: PgPool,
    chat_rooms: ChatRooms,
}

async fn get_rooms_handler(State(state): State<AppState>) -> impl IntoResponse {
    let rooms = state.chat_rooms.lock().unwrap();
    let room_names: Vec<_> = rooms.keys().cloned().collect();
    Json(room_names)
}

// --- JWT 및 시크릿 키 ---

static JWT_SECRET: Lazy<String> =
    Lazy::new(|| env::var("JWT_SECRET").expect("JWT_SECRET must be set"));

// --- 메인 함수 ---

#[tokio::main]
async fn main() {
    dotenv().ok(); // .env 파일 로드

    // 로깅 초기화
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 데이터베이스 연결 풀 생성
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to create DB pool.");
    tracing::info!("Database connected successfully");
    
    // 애플리케이션 상태 초기화
    let app_state = AppState {
        db: pool,
        chat_rooms: Arc::new(Mutex::new(HashMap::new())),
    };

    // 라우터 설정
    let app = Router::new()
        .route("/", get(|| async { Redirect::to("/static/login.html") }))
        .route("/rooms", get(get_rooms_handler))
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/ws/:room", get(websocket_handler))
        .with_state(app_state)
        // 정적 파일 서빙 (프론트엔드)
        .nest_service("/static", tower_http::services::ServeDir::new("static"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap(); // 리스너 바인딩
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()) // axum::serve 사용
        .await
        .unwrap();
}

// --- 핸들러 함수들 ---

// 회원가입 핸들러
async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<AuthPayload>,
) -> impl IntoResponse {
    let hashed_password = match hash(&payload.password, 12) {
        Ok(h) => h,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password").into_response(),
    };

    match sqlx::query_as::<_, User>(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, password_hash",
    )
    .bind(&payload.username)
    .bind(&hashed_password)
    .fetch_one(&state.db)
    .await
    {
        Ok(_) => (StatusCode::CREATED, "User created successfully").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

// 로그인 핸들러
async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<AuthPayload>,
) -> impl IntoResponse {
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(&payload.username)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    if !verify(&payload.password, &user.password_hash).unwrap_or(false) {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    let claims = Claims {
        sub: user.username.clone(),
        user_id: user.id,
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
    };

    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET.as_ref())) {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create token").into_response(),
    };
    
    use axum::http::{HeaderValue};

    let cookie = Cookie::build(("token", token.clone()))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .build();

    let mut response = Json(serde_json::json!({ "token": token })).into_response();

    // .parse() 대신 HeaderValue::from_str를 사용하여 타입을 명확히 합니다.
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );
    
    response
}

// 웹소켓 핸들러
async fn websocket_handler(
    ws: WebSocketUpgrade,
    Path(room): Path<String>,
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let token = match params.get("token") {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Token not provided").into_response(),
    };
    
    let claims = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::default(),
    ) {
        Ok(token_data) => token_data.claims,
        Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
    };
    
    ws.on_upgrade(move |socket| handle_socket(socket, addr, state, room, claims))
}

// 개별 웹소켓 연결 처리
async fn handle_socket(
    socket: WebSocket, // mut 삭제
    who: SocketAddr,
    state: AppState,
    room: String,
    claims: Claims,
) {
    let username = claims.sub;
    let user_id = claims.user_id;

    // 채팅방의 Sender를 얻거나, 없으면 새로 생성
    let tx = {
        let mut rooms = state.chat_rooms.lock().unwrap();
        rooms.entry(room.clone()).or_insert_with(|| broadcast::channel(100).0).clone()
    };
    let mut rx = tx.subscribe();
    
    tracing::info!("User '{}' ({}) joined room '{}' from {}", &username, user_id, &room, who);
    
    // 접속 메시지 브로드캐스팅
    let join_msg = format!("[{}] has joined the room.", username);
    let _ = tx.send(join_msg);
    
    // --- 소유권 문제 해결 부분 ---
    // socket을 읽기(receiver)와 쓰기(sender)로 분리
    let (mut sender, mut receiver) = socket.split();

    // 다른 사람의 메시지를 이 클라이언트에게 '전송'하는 태스크 (쓰기)
    let mut recv_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // 이 클라이언트의 메시지를 '수신'해서 처리하는 태스크 (읽기)
    let send_task_username = username.clone();
    let send_task_room = room.clone(); // room 변수를 여기서 복제합니다.
    let mut send_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(text) = msg {
                // DB에 메시지 저장
                sqlx::query("...")
                    .bind(user_id)
                    .bind(&send_task_username)
                    .bind(&send_task_room) // 복제된 room 변수를 사용합니다.
                    .bind(&text)
                    .execute(&state.db)
                    .await
                    .ok();

                let broadcast_msg = format!("{}: {}", send_task_username, text);
                let _ = tx.send(broadcast_msg);
            }
        }
    });
    
    // 한쪽 태스크가 끝나면 다른 쪽도 종료
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
    
    // 접속 종료 메시지 브로드캐스팅
    let part_msg = format!("[{}] has left the room.", username);
    // 원래 room 변수는 여전히 여기서 사용 가능합니다.
    if let Some(tx) = state.chat_rooms.lock().unwrap().get(&room) {
        let _ = tx.send(part_msg);
    }

    tracing::info!("WebSocket connection for '{}' from {} closed", username, who);
}