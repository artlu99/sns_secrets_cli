//! Port of `src/errors.ts` — the product-level error every user-facing
//! failure carries. Its message is the thing that reaches the terminal.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserError(pub String);

impl core::fmt::Display for UserError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UserError {}

impl From<crate::db::DbError> for UserError {
    fn from(error: crate::db::DbError) -> Self {
        UserError(error.to_string())
    }
}

impl From<crate::sn_api::ApiClientError> for UserError {
    fn from(error: crate::sn_api::ApiClientError) -> Self {
        UserError(error.to_string())
    }
}

impl From<crate::sync_engine::SyncError> for UserError {
    fn from(error: crate::sync_engine::SyncError) -> Self {
        UserError(error.to_string())
    }
}

impl From<crate::http::HttpError> for UserError {
    fn from(error: crate::http::HttpError) -> Self {
        UserError(error.to_string())
    }
}

impl From<crate::kdf::KdfError> for UserError {
    fn from(error: crate::kdf::KdfError) -> Self {
        UserError(error.to_string())
    }
}

impl From<crate::proto004::Proto004Error> for UserError {
    fn from(error: crate::proto004::Proto004Error) -> Self {
        UserError(error.to_string())
    }
}

impl From<crate::session::SessionError> for UserError {
    fn from(error: crate::session::SessionError) -> Self {
        UserError(error.to_string())
    }
}
