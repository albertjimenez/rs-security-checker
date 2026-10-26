//! One module per Jenkins pipeline stage.

pub mod auth;
pub mod aws;
pub mod clamav;
pub mod debsums;
pub mod docker;
pub mod hardening;
pub mod network;
pub mod persistence;
pub mod precheck;
pub mod rootkit;
pub mod web;
