//! Shared business-logic layer used by both the management API
//! (`crate::management`) and the server-rendered admin panel (`crate::admin`).
//!
//! Every mutation (validation, authorization, store writes, audit logging,
//! cross-region replication) lives here exactly once; the HTTP handlers in
//! `management.rs` and `admin/` are thin adapters that authenticate the
//! caller, parse the request, invoke a service, and render the result.

pub mod authz;
pub mod clients;
pub mod hooks;
pub mod idps;
pub mod settings;
pub mod tenants;
pub mod users;

pub use authz::Caller;
