//! Audited override for release immutability (#10).
//!
//! A released coordinate cannot be overwritten, swapped behind a tombstone or
//! deleted. Operators still need a deliberate way past that rule (fix a bad
//! publish, re-migrate) that does not make the guarantee meaningless. This
//! module is that way: an explicit request, a required reason, an authority
//! check, and an audit record on every decision.
//!
//! The value travels to the enforcement points instead of a bare `bool`, so
//! the actor and the reason are at hand when the rule fires:
//!
//! * [`ImmutabilityOverride::None`]: nobody asked. Every refusal stands.
//! * [`ImmutabilityOverride::Denied`]: the caller asked but does not hold the
//!   repository `admin` action (nor is a system admin). Every refusal stands
//!   and writes `IMMUTABILITY_DENIED`.
//! * [`ImmutabilityOverride::Granted`]: the caller asked, gave a reason, and
//!   holds the authority. A refusal is waived and writes
//!   `IMMUTABILITY_OVERRIDDEN`.
//!
//! The value is only consulted where a rule would refuse
//! ([`ImmutabilityOverride::apply`] / [`ImmutabilityOverride::on_refusal`]), so
//! a request that sends the header but touches nothing released behaves (and
//! audits) exactly as one that does not.
//!
//! HTTP callers build it with [`ImmutabilityOverride::from_request`]; background
//! callers (the migration worker) build it with
//! [`ImmutabilityOverride::granted`] from the actor and reason they recorded
//! when the job was created. The type is `Serialize`/`Deserialize` so a job can
//! carry it in its stored configuration.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::error::{AppError, Result};
use crate::services::audit_export::details::ImmutabilityOverrideDetails;
use crate::services::audit_service::{AuditAction, AuditEntry, AuditService, ResourceType};
use crate::services::permission_service::PermissionService;

/// Request header asking for the override (`true`, `1` or `yes`).
pub const OVERRIDE_HEADER: &str = "x-artifact-keeper-immutability-override";
/// Request header carrying the required reason (visible ASCII).
pub const OVERRIDE_REASON_HEADER: &str = "x-artifact-keeper-immutability-override-reason";
/// Longest reason accepted, in bytes. A longer one is refused with 400 rather
/// than truncated, so the audit trail holds exactly what the operator wrote.
pub const MAX_REASON_BYTES: usize = 1024;

/// Who exercised (or tried to exercise) an override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideActor {
    pub user_id: Uuid,
    pub username: String,
}

impl OverrideActor {
    pub fn from_auth(auth: &AuthExtension) -> Self {
        Self {
            user_id: auth.user_id,
            username: auth.username.clone(),
        }
    }
}

/// The authority an override was granted under, recorded in the audit row.
/// Spelled like the age gate's `actor_tier` (#4238).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideTier {
    /// A system administrator.
    InstanceAdmin,
    /// A principal holding the repository `admin` action, directly, through a
    /// group, or inherited from the owning project.
    RepositoryAdmin,
}

/// Where an immutability rule fired, recorded in the audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPoint {
    /// The upload oracle `enforce_path_immutability` (REST and chunked uploads).
    Upload,
    /// The pre-insert tombstone purge `cleanup_soft_deleted_artifact_checked`.
    TombstonePurge,
    /// The REST artifact delete guard.
    Delete,
    /// `DELETE ...?permanent=true` purging the trashed row (`upstream #4701`).
    TrashPurge,
    /// The migration worker replacing a released row (#3).
    Migration,
    /// Promotion or approval writing onto a released target coordinate (#1).
    Promotion,
}

/// The coordinate an override decision is about.
#[derive(Debug, Clone, Copy)]
pub struct OverrideTarget<'a> {
    pub repository_id: Uuid,
    pub path: &'a str,
    pub point: EnforcementPoint,
}

impl<'a> OverrideTarget<'a> {
    pub fn new(repository_id: Uuid, path: &'a str, point: EnforcementPoint) -> Self {
        Self {
            repository_id,
            path,
            point,
        }
    }
}

/// An immutability override request, resolved against the caller's authority.
/// See the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ImmutabilityOverride {
    #[default]
    None,
    Denied {
        actor: OverrideActor,
        reason: String,
    },
    Granted {
        actor: OverrideActor,
        reason: String,
        tier: OverrideTier,
    },
}

/// Trim and bound an override reason. Missing, blank or oversized is a 400.
fn validate_reason(reason: Option<&str>) -> Result<String> {
    let reason = reason.map(str::trim).unwrap_or_default();
    if reason.is_empty() {
        return Err(AppError::Validation(format!(
            "An immutability override requires a reason in the {OVERRIDE_REASON_HEADER} header"
        )));
    }
    if reason.len() > MAX_REASON_BYTES {
        return Err(AppError::Validation(format!(
            "The immutability override reason must be at most {MAX_REASON_BYTES} bytes"
        )));
    }
    Ok(reason.to_string())
}

/// Whether the request asks for the override (`true`, `1` or `yes`, any case).
pub fn override_requested(headers: &HeaderMap) -> bool {
    headers
        .get(OVERRIDE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}

/// The reason header. A value that is not visible ASCII is a 400 rather than a
/// silently missing reason.
fn reason_header(headers: &HeaderMap) -> Result<Option<&str>> {
    headers
        .get(OVERRIDE_REASON_HEADER)
        .map(|v| {
            v.to_str().map_err(|_| {
                AppError::Validation(format!(
                    "The {OVERRIDE_REASON_HEADER} header must be visible ASCII"
                ))
            })
        })
        .transpose()
}

impl ImmutabilityOverride {
    /// An override granted outside an HTTP request (a migration job) on
    /// behalf of `actor`, who held `tier` when the job was created. The reason
    /// is validated exactly as a request's is.
    pub fn granted(actor: OverrideActor, reason: &str, tier: OverrideTier) -> Result<Self> {
        Ok(Self::Granted {
            actor,
            reason: validate_reason(Some(reason))?,
            tier,
        })
    }

    /// The pure authorization decision behind [`Self::from_request`].
    ///
    /// * not requested: [`Self::None`];
    /// * requested with a missing, blank or oversized reason: 400, whoever asks;
    /// * requested by a principal without the authority: [`Self::Denied`] (the
    ///   refusal, and its audit, happen only if a rule actually fires);
    /// * otherwise [`Self::Granted`], under the instance tier when the caller
    ///   is a system admin.
    ///
    /// `in_token_scope` keeps a repository-restricted admin token inside its
    /// repositories, the hole the second commit of `upstream #4701` closed for
    /// the trash purge.
    pub fn decide(
        requested: bool,
        reason: Option<&str>,
        actor: OverrideActor,
        is_admin: bool,
        is_repo_admin: bool,
        in_token_scope: bool,
    ) -> Result<Self> {
        if !requested {
            return Ok(Self::None);
        }
        let reason = validate_reason(reason)?;
        let tier = match (in_token_scope, is_admin, is_repo_admin) {
            (false, _, _) => None,
            (true, true, _) => Some(OverrideTier::InstanceAdmin),
            (true, false, true) => Some(OverrideTier::RepositoryAdmin),
            (true, false, false) => None,
        };
        Ok(match tier {
            Some(tier) => Self::Granted {
                actor,
                reason,
                tier,
            },
            None => Self::Denied { actor, reason },
        })
    }

    /// Resolve the override headers of a request against the caller's
    /// authority on `repository_id`.
    ///
    /// The repository `admin` check is `require_repo_admin`, the gate the
    /// repository configuration endpoints and the repository-scoped age gate
    /// (`upstream #4238`) use, so the action held directly, via a group, or
    /// inherited from the project all count. Only its 403 maps to
    /// [`Self::Denied`]; a permission-lookup failure propagates.
    pub async fn from_request(
        headers: &HeaderMap,
        auth: &AuthExtension,
        repository_id: Uuid,
        permission_service: &PermissionService,
    ) -> Result<Self> {
        if !override_requested(headers) {
            return Ok(Self::None);
        }
        let reason = reason_header(headers)?;
        // Validate before the permission lookup, so a 400 costs no query.
        validate_reason(reason)?;
        let is_repo_admin = if auth.is_admin {
            true
        } else {
            match crate::api::handlers::repositories::require_repo_admin(
                auth,
                repository_id,
                permission_service,
            )
            .await
            {
                Ok(()) => true,
                Err(AppError::Authorization(_)) => false,
                Err(e) => return Err(e),
            }
        };
        Self::decide(
            true,
            reason,
            OverrideActor::from_auth(auth),
            auth.is_admin,
            is_repo_admin,
            auth.can_access_repo(repository_id),
        )
    }

    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }

    /// Run an enforcement point's verdict through the override: an
    /// `AppError::Immutable` refusal goes to [`Self::on_refusal`]; success and
    /// every other error pass through untouched.
    ///
    /// This is the one-line adoption for a new enforcement point:
    /// `ovr.apply(db, target, check(..).await).await`.
    pub async fn apply(
        &self,
        db: &PgPool,
        target: OverrideTarget<'_>,
        verdict: Result<()>,
    ) -> Result<()> {
        match verdict {
            Err(refusal @ AppError::Immutable(_)) => self.on_refusal(db, target, refusal).await,
            other => other,
        }
    }

    /// A rule at `target` refused with `refusal`. Decide and audit:
    ///
    /// * [`Self::None`]: `Err(refusal)`, no audit row;
    /// * [`Self::Denied`]: `Err(refusal)` and an `IMMUTABILITY_DENIED` row;
    /// * [`Self::Granted`]: `Ok(())` and an `IMMUTABILITY_OVERRIDDEN` row. The
    ///   row is written before the waived operation proceeds; if it cannot be
    ///   written the override fails closed and `refusal` stands, so no
    ///   override is ever honoured without its record.
    pub async fn on_refusal(
        &self,
        db: &PgPool,
        target: OverrideTarget<'_>,
        refusal: AppError,
    ) -> Result<()> {
        match self {
            Self::None => Err(refusal),
            Self::Denied { actor, reason } => {
                let entry = audit_entry(
                    AuditAction::ImmutabilityDenied,
                    actor,
                    reason,
                    None,
                    &target,
                    &refusal,
                );
                if let Err(e) = AuditService::new(db.clone()).log(entry).await {
                    tracing::warn!(error = %e, "IMMUTABILITY_DENIED audit write failed");
                }
                Err(refusal)
            }
            Self::Granted {
                actor,
                reason,
                tier,
            } => {
                let entry = audit_entry(
                    AuditAction::ImmutabilityOverridden,
                    actor,
                    reason,
                    Some(*tier),
                    &target,
                    &refusal,
                );
                match AuditService::new(db.clone()).log(entry).await {
                    Ok(_) => {
                        tracing::warn!(
                            repository_id = %target.repository_id,
                            path = target.path,
                            actor = %actor.username,
                            "release immutability overridden"
                        );
                        Ok(())
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "IMMUTABILITY_OVERRIDDEN audit write failed; refusing the override"
                        );
                        Err(refusal)
                    }
                }
            }
        }
    }
}

fn audit_entry(
    action: AuditAction,
    actor: &OverrideActor,
    reason: &str,
    tier: Option<OverrideTier>,
    target: &OverrideTarget<'_>,
    refusal: &AppError,
) -> AuditEntry {
    AuditEntry::new(action, ResourceType::Repository)
        .user(actor.user_id)
        .actor_name(actor.username.clone())
        .resource(target.repository_id)
        .resource_name(target.path.to_string())
        .details_typed(ImmutabilityOverrideDetails {
            repository_id: target.repository_id,
            path: target.path.to_string(),
            enforcement_point: target.point,
            reason: reason.to_string(),
            actor_tier: tier,
            refusal: refusal.to_string(),
        })
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    fn actor() -> OverrideActor {
        OverrideActor {
            user_id: Uuid::new_v4(),
            username: "ops".to_string(),
        }
    }

    /// `decide` for a request with `reason`, by a caller holding the given
    /// authority, inside its token scope.
    fn decide(
        reason: Option<&str>,
        is_admin: bool,
        is_repo_admin: bool,
    ) -> Result<ImmutabilityOverride> {
        ImmutabilityOverride::decide(true, reason, actor(), is_admin, is_repo_admin, true)
    }

    #[test]
    fn not_requested_is_none_whatever_the_caller() {
        let ovr = ImmutabilityOverride::decide(false, None, actor(), true, true, true).unwrap();
        assert_eq!(ovr, ImmutabilityOverride::None);
        assert!(!ovr.is_granted());
    }

    #[test]
    fn non_admin_with_the_flag_is_denied() {
        let ovr = decide(Some("fix it"), false, false).unwrap();
        assert!(
            matches!(&ovr, ImmutabilityOverride::Denied { reason, .. } if reason == "fix it"),
            "{ovr:?}"
        );
        assert!(!ovr.is_granted());
    }

    #[test]
    fn admin_without_a_reason_is_a_400() {
        for (is_admin, is_repo_admin) in [(true, false), (false, true), (false, false)] {
            for reason in [None, Some(""), Some("   ")] {
                let err = decide(reason, is_admin, is_repo_admin).unwrap_err();
                assert!(matches!(err, AppError::Validation(_)), "{err:?}");
            }
        }
        let long = "x".repeat(MAX_REASON_BYTES + 1);
        assert!(matches!(
            decide(Some(&long), true, false),
            Err(AppError::Validation(_))
        ));
        assert!(decide(Some(&"x".repeat(MAX_REASON_BYTES)), true, false).is_ok());
    }

    #[test]
    fn admin_with_a_reason_is_granted_under_its_tier() {
        let repo_admin = decide(Some("  INC-42 rebuild  "), false, true).unwrap();
        assert!(
            matches!(
                &repo_admin,
                ImmutabilityOverride::Granted { reason, tier: OverrideTier::RepositoryAdmin, .. }
                    if reason == "INC-42 rebuild"
            ),
            "{repo_admin:?}"
        );
        let instance = decide(Some("INC-42"), true, false).unwrap();
        assert!(matches!(
            instance,
            ImmutabilityOverride::Granted {
                tier: OverrideTier::InstanceAdmin,
                ..
            }
        ));
        assert!(instance.is_granted());
    }

    #[test]
    fn a_token_outside_the_repository_is_denied_even_for_an_admin() {
        let ovr =
            ImmutabilityOverride::decide(true, Some("x"), actor(), true, true, false).unwrap();
        assert!(
            matches!(ovr, ImmutabilityOverride::Denied { .. }),
            "{ovr:?}"
        );
    }

    #[test]
    fn the_flag_header_accepts_true_1_and_yes() {
        for value in ["true", "TRUE", "1", "yes", " yes "] {
            let mut headers = HeaderMap::new();
            headers.insert(OVERRIDE_HEADER, value.parse().unwrap());
            assert!(override_requested(&headers), "{value}");
        }
        for value in ["false", "0", ""] {
            let mut headers = HeaderMap::new();
            headers.insert(OVERRIDE_HEADER, value.parse().unwrap());
            assert!(!override_requested(&headers), "{value}");
        }
        assert!(!override_requested(&HeaderMap::new()));
    }

    #[test]
    fn a_reason_that_is_not_visible_ascii_is_a_400() {
        let mut headers = tdh::immutability_override_headers(None);
        headers.insert(
            OVERRIDE_REASON_HEADER,
            axum::http::HeaderValue::from_bytes(b"caf\xe9").unwrap(),
        );
        assert!(matches!(
            reason_header(&headers),
            Err(AppError::Validation(_))
        ));
        assert_eq!(
            reason_header(&tdh::immutability_override_headers(Some("ok"))).unwrap(),
            Some("ok")
        );
    }

    #[test]
    fn granted_validates_the_reason_and_round_trips_through_json() {
        assert!(ImmutabilityOverride::granted(actor(), " ", OverrideTier::InstanceAdmin).is_err());
        let ovr =
            ImmutabilityOverride::granted(actor(), "re-migrate", OverrideTier::RepositoryAdmin)
                .unwrap();
        let json = serde_json::to_value(&ovr).unwrap();
        assert_eq!(json["decision"], "granted");
        assert_eq!(json["tier"], "repository_admin");
        let back: ImmutabilityOverride = serde_json::from_value(json).unwrap();
        assert_eq!(back, ovr);
        let none: ImmutabilityOverride = serde_json::from_str(r#"{"decision":"none"}"#).unwrap();
        assert_eq!(none, ImmutabilityOverride::None);
    }

    #[tokio::test]
    async fn none_keeps_every_refusal_and_apply_passes_other_verdicts_through() {
        // No DB access happens on these paths: the lazy pool never connects.
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .unwrap();
        let target = OverrideTarget::new(Uuid::new_v4(), "a/1.0/a.jar", EnforcementPoint::Upload);
        let none = ImmutabilityOverride::None;
        let refused = none
            .apply(&db, target, Err(AppError::Immutable("no".into())))
            .await;
        assert!(matches!(refused, Err(AppError::Immutable(_))));
        assert!(none.apply(&db, target, Ok(())).await.is_ok());
        // A non-immutability error is never waived, even by a granted override.
        let granted =
            ImmutabilityOverride::granted(actor(), "x", OverrideTier::InstanceAdmin).unwrap();
        let other = granted
            .apply(&db, target, Err(AppError::Conflict("quota".into())))
            .await;
        assert!(matches!(other, Err(AppError::Conflict(_))));
        assert!(granted.apply(&db, target, Ok(())).await.is_ok());
    }

    /// `from_request` resolves the repository `admin` action through the
    /// `upstream #4238` gate, and `on_refusal` records both decisions.
    #[tokio::test]
    async fn from_request_and_on_refusal_record_each_decision_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (member, member_name) = tdh::create_user(&pool).await;
        let (owner, owner_name) = tdh::create_user(&pool).await;
        tdh::grant_repo_admin(&pool, repo_id, owner).await;
        let permissions = PermissionService::new(pool.clone());
        let headers = tdh::immutability_override_headers(Some("INC-42 rebuild"));
        let target = OverrideTarget::new(repo_id, "app/1.0/app.bin", EnforcementPoint::Upload);
        let refusal = || AppError::Immutable("immutable".into());

        let none = ImmutabilityOverride::from_request(
            &HeaderMap::new(),
            &tdh::make_auth(member, &member_name),
            repo_id,
            &permissions,
        )
        .await;
        let denied = ImmutabilityOverride::from_request(
            &headers,
            &tdh::make_auth(member, &member_name),
            repo_id,
            &permissions,
        )
        .await
        .unwrap();
        let granted = ImmutabilityOverride::from_request(
            &headers,
            &tdh::make_auth(owner, &owner_name),
            repo_id,
            &permissions,
        )
        .await
        .unwrap();
        let no_reason = ImmutabilityOverride::from_request(
            &tdh::immutability_override_headers(None),
            &tdh::make_auth(owner, &owner_name),
            repo_id,
            &permissions,
        )
        .await;

        let denied_verdict = denied.on_refusal(&pool, target, refusal()).await;
        let denied_row = tdh::audit_row_eventually(&pool, repo_id, "IMMUTABILITY_DENIED").await;
        let granted_verdict = granted.on_refusal(&pool, target, refusal()).await;
        let granted_row =
            tdh::audit_row_eventually(&pool, repo_id, "IMMUTABILITY_OVERRIDDEN").await;
        tdh::cleanup(&pool, repo_id, member).await;
        tdh::cleanup(&pool, repo_id, owner).await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(none.unwrap(), ImmutabilityOverride::None);
        assert!(
            matches!(denied, ImmutabilityOverride::Denied { .. }),
            "{denied:?}"
        );
        assert!(
            matches!(
                granted,
                ImmutabilityOverride::Granted {
                    tier: OverrideTier::RepositoryAdmin,
                    ..
                }
            ),
            "{granted:?}"
        );
        assert!(matches!(no_reason, Err(AppError::Validation(_))));
        assert!(matches!(denied_verdict, Err(AppError::Immutable(_))));
        assert_eq!(denied_row.user_id, Some(member));
        assert_eq!(denied_row.details["reason"], "INC-42 rebuild");
        assert!(denied_row.details.get("actor_tier").is_none());
        assert!(granted_verdict.is_ok());
        assert_eq!(granted_row.user_id, Some(owner));
        assert_eq!(granted_row.resource_type, "repository");
        assert_eq!(granted_row.details["enforcement_point"], "upload");
        assert_eq!(granted_row.details["actor_tier"], "repository_admin");
        assert_eq!(granted_row.details["path"], "app/1.0/app.bin");
    }
}
