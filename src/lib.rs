mod client;

pub use client::{NatpmpPortMappingService, PortMappingResponse, PortMappingService};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use natpmp::Protocol;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{error, info};

pub type ClientFactory = Arc<dyn Fn() -> Result<Box<dyn PortMappingService>, String> + Send + Sync>;

#[derive(Clone)]
pub struct AppState {
    pub gateway: IpAddr,
    pub max_duration: Option<u32>,
    pub token: Option<String>,
    pub client_factory: ClientFactory,
}

#[derive(Deserialize)]
pub struct ForwardRequest {
    pub internal_port: u16,
    pub protocol: String,
    pub duration: u32,
}

#[derive(Serialize, Deserialize)]
pub struct ForwardResponse {
    pub internal_port: u16,
    pub external_port: u16,
    pub protocol: String,
    pub duration: u32,
}

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub fn check_authorization(headers: &HeaderMap, expected_token: &Option<String>) -> bool {
    match expected_token {
        None => true, // No token required
        Some(token) => {
            if let Some(auth_header) = headers.get("authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    return auth_str == format!("Bearer {}", token);
                }
            }
            false
        }
    }
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

pub async fn forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ForwardRequest>,
) -> Result<Json<ForwardResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check authorization
    if !check_authorization(&headers, &state.token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Unauthorized".to_string(),
            }),
        ));
    }

    // Validate and clamp duration
    let duration = match state.max_duration {
        Some(max) => payload.duration.min(max),
        None => payload.duration, // No limit if max_duration is -1
    };

    // Create NAT-PMP client using the factory
    let mut client = match (state.client_factory)() {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create NAT-PMP client: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create NAT-PMP client".to_string(),
                }),
            ));
        }
    };

    // Request port mapping (validates protocol implicitly)
    let protocol_enum = match payload.protocol.to_lowercase().as_str() {
        "tcp" => Protocol::TCP,
        "udp" => Protocol::UDP,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "protocol must be tcp or udp".to_string(),
                }),
            ));
        }
    };

    // Request port mapping
    match client.request_port_mapping(
        protocol_enum,
        payload.internal_port,
        0, // Let NAT-PMP choose external port
        duration,
    ) {
        Ok(response) => {
            info!(
                "Created mapping: {}/{} -> {} (duration: {}s)",
                payload.internal_port,
                payload.protocol.to_lowercase(),
                response.external_port,
                duration
            );

            Ok(Json(ForwardResponse {
                internal_port: payload.internal_port,
                external_port: response.external_port,
                protocol: payload.protocol.to_lowercase(),
                duration,
            }))
        }
        Err(e) => {
            error!("Failed to request port mapping: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to request port mapping".to_string(),
                }),
            ))
        }
    }
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/forward", post(forward))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Unit Tests ==========

    #[test]
    fn test_check_authorization_no_token_required() {
        let headers = HeaderMap::new();
        let expected_token = None;
        assert!(check_authorization(&headers, &expected_token));
    }

    #[test]
    fn test_check_authorization_valid_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer my-secret-token".parse().unwrap());
        let expected_token = Some("my-secret-token".to_string());
        assert!(check_authorization(&headers, &expected_token));
    }

    #[test]
    fn test_check_authorization_invalid_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer wrong-token".parse().unwrap());
        let expected_token = Some("my-secret-token".to_string());
        assert!(!check_authorization(&headers, &expected_token));
    }

    #[test]
    fn test_check_authorization_missing_header() {
        let headers = HeaderMap::new();
        let expected_token = Some("my-secret-token".to_string());
        assert!(!check_authorization(&headers, &expected_token));
    }

    #[test]
    fn test_check_authorization_malformed_header() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "InvalidFormat".parse().unwrap());
        let expected_token = Some("my-secret-token".to_string());
        assert!(!check_authorization(&headers, &expected_token));
    }

    #[test]
    fn test_forward_request_deserialization() {
        let json = r#"{"internal_port": 8080, "protocol": "tcp", "duration": 300}"#;
        let req: ForwardRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.internal_port, 8080);
        assert_eq!(req.protocol, "tcp");
        assert_eq!(req.duration, 300);
    }

    #[test]
    fn test_forward_response_serialization() {
        let response = ForwardResponse {
            internal_port: 8080,
            external_port: 12345,
            protocol: "tcp".to_string(),
            duration: 300,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"internal_port\":8080"));
        assert!(json.contains("\"external_port\":12345"));
        assert!(json.contains("\"protocol\":\"tcp\""));
        assert!(json.contains("\"duration\":300"));
    }

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"timestamp\":\"2024-01-01T00:00:00Z\""));
    }

    #[test]
    fn test_error_response_serialization() {
        let response = ErrorResponse {
            error: "Test error".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"error\":\"Test error\""));
    }

    // ========== Integration Tests ==========

    use crate::client::MockPortMappingService;
    use axum::body::Body;
    use axum::http::{header, Request};
    use mockall::predicate::*;
    use std::net::Ipv4Addr;
    use tower::ServiceExt; // For oneshot

    fn create_test_app(client_factory: ClientFactory) -> Router {
        let state = AppState {
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            max_duration: Some(300),
            token: Some("test-token".to_string()),
            client_factory,
        };

        create_router(state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let mock_factory: ClientFactory = Arc::new(|| Err("Should not be called".to_string()));
        let app = create_test_app(mock_factory);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(health.status, "healthy");
    }

    #[tokio::test]
    async fn test_forward_unauthorized() {
        let mock_factory: ClientFactory = Arc::new(|| Err("Should not be called".to_string()));
        let app = create_test_app(mock_factory);

        let request_body = serde_json::json!({
            "internal_port": 8080,
            "protocol": "tcp",
            "duration": 300
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forward")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_forward_invalid_protocol() {
        let mock_factory: ClientFactory = Arc::new(|| {
            let mock = MockPortMappingService::new();
            // Mock should be created but no methods should be called
            // because protocol validation happens before any client operations
            Ok(Box::new(mock) as Box<dyn PortMappingService>)
        });
        let app = create_test_app(mock_factory);

        let request_body = serde_json::json!({
            "internal_port": 8080,
            "protocol": "invalid",
            "duration": 300
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forward")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert!(error.error.contains("protocol must be tcp or udp"));
    }

    #[tokio::test]
    async fn test_forward_success_tcp() {
        let mock_factory: ClientFactory = Arc::new(|| {
            let mut mock = MockPortMappingService::new();

            mock.expect_request_port_mapping()
                .with(eq(Protocol::TCP), eq(8080), eq(0), eq(300))
                .times(1)
                .returning(|_, _, _, _| {
                    Ok(PortMappingResponse {
                        external_port: 12345,
                    })
                });

            Ok(Box::new(mock) as Box<dyn PortMappingService>)
        });
        let app = create_test_app(mock_factory);

        let request_body = serde_json::json!({
            "internal_port": 8080,
            "protocol": "tcp",
            "duration": 300
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forward")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let forward_response: ForwardResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(forward_response.internal_port, 8080);
        assert_eq!(forward_response.external_port, 12345);
        assert_eq!(forward_response.protocol, "tcp");
        assert_eq!(forward_response.duration, 300);
    }

    #[tokio::test]
    async fn test_forward_success_udp() {
        let mock_factory: ClientFactory = Arc::new(|| {
            let mut mock = MockPortMappingService::new();

            mock.expect_request_port_mapping()
                .with(eq(Protocol::UDP), eq(9999), eq(0), eq(150))
                .times(1)
                .returning(|_, _, _, _| {
                    Ok(PortMappingResponse {
                        external_port: 54321,
                    })
                });

            Ok(Box::new(mock) as Box<dyn PortMappingService>)
        });
        let app = create_test_app(mock_factory);

        let request_body = serde_json::json!({
            "internal_port": 9999,
            "protocol": "UDP",
            "duration": 150
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forward")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let forward_response: ForwardResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(forward_response.internal_port, 9999);
        assert_eq!(forward_response.external_port, 54321);
        assert_eq!(forward_response.protocol, "udp");
        assert_eq!(forward_response.duration, 150);
    }

    #[tokio::test]
    async fn test_forward_client_creation_failure() {
        let mock_factory: ClientFactory = Arc::new(|| Err("Failed to create client".to_string()));
        let app = create_test_app(mock_factory);

        let request_body = serde_json::json!({
            "internal_port": 8080,
            "protocol": "tcp",
            "duration": 300
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forward")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_forward_request_failure() {
        let mock_factory: ClientFactory = Arc::new(|| {
            let mut mock = MockPortMappingService::new();

            mock.expect_request_port_mapping()
                .times(1)
                .returning(|_, _, _, _| Err("Network error".to_string()));

            Ok(Box::new(mock) as Box<dyn PortMappingService>)
        });
        let app = create_test_app(mock_factory);

        let request_body = serde_json::json!({
            "internal_port": 8080,
            "protocol": "tcp",
            "duration": 300
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forward")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_forward_duration_clamping() {
        let mock_factory: ClientFactory = Arc::new(|| {
            let mut mock = MockPortMappingService::new();

            // Should clamp 1000 to 300 (max_duration)
            mock.expect_request_port_mapping()
                .with(eq(Protocol::TCP), eq(8080), eq(0), eq(300))
                .times(1)
                .returning(|_, _, _, _| {
                    Ok(PortMappingResponse {
                        external_port: 12345,
                    })
                });

            Ok(Box::new(mock) as Box<dyn PortMappingService>)
        });
        let app = create_test_app(mock_factory);

        let request_body = serde_json::json!({
            "internal_port": 8080,
            "protocol": "tcp",
            "duration": 1000
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forward")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let forward_response: ForwardResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(forward_response.duration, 300); // Clamped to max
    }
}
