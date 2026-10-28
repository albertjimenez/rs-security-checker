//! One module per Jenkins pipeline stage.

pub mod auth;
pub mod aws;
pub mod broad_secrets;
pub mod ca_trust;
pub mod clamav;
pub mod debsums;
pub mod docker;
pub mod hardening;
pub mod mount_mac;
pub mod network;
pub mod persistence;
pub mod precheck;
pub mod process_forensics;
pub mod rootkit;
pub mod web;
