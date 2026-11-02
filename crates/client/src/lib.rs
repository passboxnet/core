//! Passbox client for native apps and the CLI: sign-up, sign-in, online and
//! offline unlock, incremental sync with an encrypted offline cache, and
//! item editing with conflict detection.
//!
//! The browser clients use the equivalent TypeScript implementation in
//! `packages/client`; both talk to the same API and share the item format.

pub mod agent;
pub mod api;
pub mod client;
pub mod error;
pub mod model;
pub mod reference;
pub mod security;
pub mod service_account;
pub mod site_icons;
pub mod store;

pub use api::{AccountEvent, SecurityKeyInfo, SessionInfo, TotpSetup, TwoFactorStatus};
pub use client::analysis::{
    ALIAS_TAG, AliasProvider, AliasService, AliasTransport, BREACH_CATALOG_KEY, CatalogStatus,
    EmailBreach, EmailMonitoring, MonitoredEmail, ReportOptions, alias_field, create_alias_with,
};
pub use client::comfort::MoveOutcome;
pub use client::developer::{AgentGrantRecord, ServiceAccountGrant, ServiceAccountInfo};
pub use client::item_tools::{
    BreachMode, BreachRange, BreachedItem, BulkFailure, HibpRange, ItemHealth, ItemProblem,
    ItemUsage, ItemVersion, UsageKind,
};
pub use client::recovery::{
    CliLoginInfo, CliLoginPoll, CliLoginStart, CodeRecoveryStart, DeviceLinkStart, DeviceLinkState,
    EmergencyContact, EmergencyContacts, EmergencyVaults, LinkedAccount, OrgRecovery,
    PendingOrgRecovery, RecoveryRequest, RecoveryResult, RecoveryStatus,
};
pub use client::sharing::{
    Invitation, InvitationInfo, InvitationPreview, VaultAccess, parse_invitation_link,
};
pub use client::{Client, Connectivity, Status};
pub use error::{Error, Result};
pub use model::{
    Attachment, DeviceAccount, FieldType, Item, ItemCategory, ItemData, ItemField, Vault, field,
    format,
};
pub use passbox_core::analysis::{
    CatalogInfo, CategorySummary, Finding, FindingKind, FixAction, Priority, Rating,
    SecurityReport, Severity,
    breaches::{BreachCatalog, BreachedSite, SiteBreach},
    lookalike::{Lookalike, LookalikeReason},
    sites::SiteSupport,
};
pub use passbox_core::sharing::state::{
    DirectoryLookup, GroupView, MemberView, OrgView, SharedVaultView, SharingView, VaultMemberView,
    Warning,
};
pub use service_account::{ServiceAccountClient, ServiceVault};
pub use store::{FileStore, MemoryStore, Store};
