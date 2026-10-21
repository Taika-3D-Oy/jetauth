use http::{Response, StatusCode};

/// Typed API error: an HTTP status, a client-safe message, and optional
/// internal detail that is logged server-side but never sent to the client.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    /// Client-safe message rendered into the JSON error body.
    pub message: String,
    /// Internal diagnostic detail — logged, never included in the response.
    pub detail: Option<String>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            detail: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    pub fn too_many(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, message)
    }

    /// Internal failure: the client receives a generic "internal error" body;
    /// the real detail is only available via `log_detail` for server-side logs.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal error".to_string(),
            detail: Some(detail.into()),
        }
    }

    /// Attach internal-only detail to an error (kept out of the response body).
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The string to log server-side: internal detail when present,
    /// otherwise the client-safe message.
    pub fn log_detail(&self) -> &str {
        self.detail.as_deref().unwrap_or(&self.message)
    }

    /// Render the OAuth-style JSON error response for this error.
    pub fn render(&self) -> Response<String> {
        crate::error_json(self.status, &self.message)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.status.as_u16())
    }
}

impl std::error::Error for ApiError {}

/// Unmigrated `Result<_, String>` call sites keep their historic behavior:
/// a plain string error maps to HTTP 400 invalid_request.
impl From<String> for ApiError {
    fn from(message: String) -> Self {
        Self::bad_request(message)
    }
}

impl From<&str> for ApiError {
    fn from(message: &str) -> Self {
        Self::bad_request(message)
    }
}
