//! The release blocklist API (upstream #4812, P2).
//!
//! `POST /api/v1/repositories/{key}/releases/{coordinate}/block` revokes a
//! release without deleting or overwriting it, and `.../unblock` restores it.
//! While blocked, every file of the release refuses download with a 403
//! (`release_block_service::enforce_download_allowed`). The bytes stay, so the
//! immutability backstops still hold the coordinate.
//!
//! `{coordinate}` is the version when the body (or, on `GET`, the query) names
//! the package `name`, and otherwise the URL-encoded path of a single file, for
//! formats whose files carry no version.
//!
//! Blocking and unblocking are held by the repository's `admin` action or an
//! instance admin, the same gate as the repository's other configuration
//! (`require_repo_admin`). A refused download never carries the reason
//! (upstream #2912). The authenticated `GET` discloses it under the same rule
//! as a quarantine reason (`GET /api/v1/quarantine/{id}`): only to a caller who
//! holds the repository, not to one who can merely read it because it is
//! public. Who placed the block goes only to the repository's admins.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::repositories::{
    require_repo_admin, require_repo_id_visible, require_repo_write_access,
};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::Repository;
use crate::services::audit_export::details::ReleaseBlockDetails;
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::release_block_service::{self as blocks, ReleaseBlock, ReleaseCoordinate};
use crate::services::repository_service::{RepoAccess, RepositoryService};

/// Mounted under `/api/v1/repositories`.
pub fn repo_router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:key/releases/:coordinate/block",
            get(get_release_block).post(block_release),
        )
        .route("/:key/releases/:coordinate/unblock", post(unblock_release))
}

fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))
}

/// Body of a block or unblock request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReleaseBlockRequest {
    /// Why the release is being blocked or unblocked. Required, at most 4096
    /// characters. Recorded in the audit trail; on a block it is also kept
    /// with the block.
    #[serde(default)]
    pub reason: String,
    /// The package name as stored on its artifacts. With it, `{coordinate}`
    /// is the version and the request covers every file of that version;
    /// without it, `{coordinate}` is the URL-encoded path of one file.
    #[serde(default)]
    pub name: Option<String>,
}

/// Query of `GET .../releases/{coordinate}/block`.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ReleaseBlockQuery {
    /// The package name; see [`ReleaseBlockRequest::name`].
    pub name: Option<String>,
}

/// A release block.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReleaseBlockResponse {
    pub id: Uuid,
    pub repository_key: String,
    /// Package name, for a version block.
    pub name: Option<String>,
    /// Version, for a version block.
    pub version: Option<String>,
    /// File path, for a single-file block.
    pub path: Option<String>,
    /// `block`.
    pub mode: String,
    /// The reason the block was placed with. On `GET`, returned only to a
    /// caller who holds the repository (an instance admin or a principal with
    /// `read` on it), exactly as a quarantine reason is; `None` for a caller
    /// who can see the repository only because it is public.
    pub reason: Option<String>,
    /// Who placed the block. Returned only to the repository's admins (and on
    /// block / unblock, which only they can call); `None` otherwise, and once
    /// that account is deleted.
    pub blocked_by: Option<Uuid>,
    pub blocked_by_username: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// What a [`ReleaseBlockResponse`] may disclose to its caller.
#[derive(Debug, Clone, Copy)]
struct Disclosure {
    reason: bool,
    actor: bool,
}

impl Disclosure {
    /// Block and unblock: the caller is a repository admin.
    const ADMIN: Self = Self {
        reason: true,
        actor: true,
    };
}

fn to_response(
    repository_key: &str,
    block: ReleaseBlock,
    disclose: Disclosure,
) -> ReleaseBlockResponse {
    ReleaseBlockResponse {
        id: block.id,
        repository_key: repository_key.to_string(),
        name: block.name,
        version: block.version,
        path: block.path,
        mode: block.mode,
        reason: disclose.reason.then_some(block.reason),
        blocked_by: block.actor_id.filter(|_| disclose.actor),
        blocked_by_username: block.actor_name.filter(|_| disclose.actor),
        created_at: block.created_at,
    }
}

/// What the `GET` discloses to `auth` about a block in `repository_id`.
///
/// The reason follows the quarantine reason gate (`get_quarantine_status`,
/// #2912 / #3174): token scope covers the repository AND the caller is an
/// instance admin or holds `read` on it. The `is_public` arm of visibility is
/// deliberately not enough. The actor additionally needs the repository
/// `admin` action.
async fn disclosure_for(
    state: &SharedState,
    auth: &AuthExtension,
    repository_id: Uuid,
) -> Result<Disclosure> {
    if !auth.can_access_repo(repository_id) {
        return Ok(Disclosure {
            reason: false,
            actor: false,
        });
    }
    let reason = auth.is_admin
        || RepositoryService::new(state.db.clone())
            .user_can_access_repo(repository_id, auth.user_id, RepoAccess::READ)
            .await?;
    let actor = reason
        && require_repo_admin(auth, repository_id, &state.permission_service)
            .await
            .is_ok();
    Ok(Disclosure { reason, actor })
}

fn actor_tier_label(auth: &AuthExtension) -> &'static str {
    if auth.is_admin {
        "instance_admin"
    } else {
        "repository_admin"
    }
}

/// Resolve `key` and require the repository `admin` action (or an instance
/// admin) on it.
async fn authorize_release_admin(
    state: &SharedState,
    auth: &AuthExtension,
    key: &str,
) -> Result<Repository> {
    auth.require_scope("write:repositories")?;
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(key).await?;
    require_repo_write_access(auth, &repo, &service).await?;
    require_repo_admin(auth, repo.id, &state.permission_service).await?;
    Ok(repo)
}

/// Audit a block or unblock and publish its webhook event.
async fn record_block_action(
    state: &SharedState,
    auth: &AuthExtension,
    repo: &Repository,
    (action, event): (AuditAction, &str),
    block: &ReleaseBlock,
    reason: &str,
    block_reason: Option<String>,
) {
    audit_fire_and_forget(
        state.db.clone(),
        AuditEntry::for_principal(action, ResourceType::Repository, auth)
            .resource(repo.id)
            .resource_name(repo.key.clone())
            .details_typed(ReleaseBlockDetails {
                block_id: block.id,
                repository_key: repo.key.clone(),
                name: block.name.clone(),
                version: block.version.clone(),
                path: block.path.clone(),
                mode: block.mode.clone(),
                reason: reason.to_string(),
                actor_tier: actor_tier_label(auth).to_string(),
                block_reason,
            }),
    )
    .await;
    state
        .event_bus
        .emit_for_repo(event, block.id, repo.id, Some(auth.username.clone()));
}

/// Block a release
#[utoipa::path(
    post,
    path = "/{key}/releases/{coordinate}/block",
    context_path = "/api/v1/repositories",
    tag = "release-blocks",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("coordinate" = String, Path, description = "The version when `name` is given, otherwise the URL-encoded file path"),
    ),
    request_body = ReleaseBlockRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "Release blocked: every file of it now refuses download with 403", body = ReleaseBlockResponse),
        (status = 400, description = "Missing or over-long reason, or an empty coordinate or name", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Repository admin permission is required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository not found, or no artifact matches the coordinate", body = crate::api::openapi::ErrorResponse),
        (status = 409, description = "The release is already blocked", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn block_release(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, coordinate)): Path<(String, String)>,
    Json(req): Json<ReleaseBlockRequest>,
) -> Result<(StatusCode, Json<ReleaseBlockResponse>)> {
    let auth = require_auth(auth)?;
    // The request is validated before authorization, so a missing or blank
    // reason is a 400 whoever sends it, as on the audited override (#10).
    let coordinate = ReleaseCoordinate::parse(&coordinate, req.name.as_deref())?;
    let reason = blocks::validate_reason(&req.reason)?;
    let repo = authorize_release_admin(&state, &auth, &key).await?;
    let block = blocks::block(
        &state.db,
        repo.id,
        &coordinate,
        reason,
        auth.user_id,
        &auth.username,
    )
    .await?;
    let reason = block.reason.clone();
    record_block_action(
        &state,
        &auth,
        &repo,
        (AuditAction::ReleaseBlocked, "release.blocked"),
        &block,
        &reason,
        None,
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(to_response(&repo.key, block, Disclosure::ADMIN)),
    ))
}

/// Unblock a release
#[utoipa::path(
    post,
    path = "/{key}/releases/{coordinate}/unblock",
    context_path = "/api/v1/repositories",
    tag = "release-blocks",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("coordinate" = String, Path, description = "The version when `name` is given, otherwise the URL-encoded file path"),
    ),
    request_body = ReleaseBlockRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Block lifted; the lifted block is returned", body = ReleaseBlockResponse),
        (status = 400, description = "Missing or over-long reason, or an empty coordinate or name", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Repository admin permission is required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository not found, or the release is not blocked", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn unblock_release(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, coordinate)): Path<(String, String)>,
    Json(req): Json<ReleaseBlockRequest>,
) -> Result<Json<ReleaseBlockResponse>> {
    let auth = require_auth(auth)?;
    // Validated before authorization, as in `block_release`.
    let coordinate = ReleaseCoordinate::parse(&coordinate, req.name.as_deref())?;
    let reason = blocks::validate_reason(&req.reason)?.to_string();
    let repo = authorize_release_admin(&state, &auth, &key).await?;
    let block = blocks::unblock(&state.db, repo.id, &coordinate).await?;
    record_block_action(
        &state,
        &auth,
        &repo,
        (AuditAction::ReleaseUnblocked, "release.unblocked"),
        &block,
        &reason,
        Some(block.reason.clone()),
    )
    .await;
    Ok(Json(to_response(&repo.key, block, Disclosure::ADMIN)))
}

/// Read a release block
///
/// The only place a block's reason is disclosed. Any authenticated caller who
/// can see the repository learns whether the release is blocked; the reason
/// goes only to a caller who holds the repository (as for a quarantine reason),
/// and who placed the block only to its admins. A refused download carries
/// neither.
#[utoipa::path(
    get,
    path = "/{key}/releases/{coordinate}/block",
    context_path = "/api/v1/repositories",
    tag = "release-blocks",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("coordinate" = String, Path, description = "The version when `name` is given, otherwise the URL-encoded file path"),
        ReleaseBlockQuery,
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The release is blocked", body = ReleaseBlockResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found, or the release is not blocked", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn get_release_block(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, coordinate)): Path<(String, String)>,
    Query(query): Query<ReleaseBlockQuery>,
) -> Result<Json<ReleaseBlockResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("read:repositories")?;
    let repo = RepositoryService::new(state.db.clone())
        .get_by_key(&key)
        .await?;
    // Existence gate, as `get_quarantine_status`: a repository the caller
    // cannot see is the same 404 as one that does not exist.
    require_repo_id_visible(
        &state.db,
        &auth,
        repo.id,
        crate::api::handlers::repositories::REPOSITORY_NOT_FOUND,
    )
    .await?;
    let coordinate = ReleaseCoordinate::parse(&coordinate, query.name.as_deref())?;
    let block = blocks::get(&state.db, repo.id, &coordinate)
        .await?
        .ok_or_else(|| AppError::NotFound("This release is not blocked".to_string()))?;
    let disclose = disclosure_for(&state, &auth, repo.id).await?;
    Ok(Json(to_response(&repo.key, block, disclose)))
}

#[derive(OpenApi)]
#[openapi(
    paths(block_release, unblock_release, get_release_block),
    components(schemas(ReleaseBlockRequest, ReleaseBlockResponse)),
    tags((name = "release-blocks", description = "Release blocklist: revoke a release without deleting it"))
)]
pub struct ReleaseBlocksApiDoc;

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::repositories::download_router;
    use crate::api::handlers::test_db_helpers as tdh;
    use bytes::Bytes;

    fn json_post(uri: String, body: serde_json::Value) -> axum::http::Request<axum::body::Body> {
        tdh::post(
            uri,
            "application/json",
            Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
    }

    fn app(fx: &tdh::Fixture, auth: Option<AuthExtension>) -> Router {
        let router = repo_router().merge(download_router());
        match auth {
            Some(auth) => tdh::router_with_auth(router, fx.state.clone(), auth),
            None => fx.router_anon(router),
        }
    }

    /// Seed one stored file of `name`/`version` at `path`.
    async fn seed(fx: &tdh::Fixture, path: &str, name: &str, version: &str) -> Uuid {
        let repo = fx.repo_info("local", None);
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            &format!("rb-handler/{}.bin", Uuid::new_v4()),
            path,
            name,
            version,
            "application/octet-stream",
            Bytes::from(format!("bytes of {path}")),
            fx.user_id,
        )
        .await
    }

    async fn download(
        fx: &tdh::Fixture,
        auth: Option<AuthExtension>,
        path: &str,
    ) -> (StatusCode, String) {
        let (status, body) = tdh::send(
            app(fx, auth),
            tdh::get(format!("/{}/download/{path}", fx.repo_key)),
        )
        .await;
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn repo_admin(fx: &tdh::Fixture) -> AuthExtension {
        tdh::make_auth(fx.user_id, &fx.username)
    }

    /// Block -> every file of the version is a 403 and other versions still
    /// serve; unblock -> 200 again. Both actions are audited.
    #[tokio::test]
    async fn block_refuses_every_file_of_the_version_until_unblocked_db() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        tdh::grant_repo_admin(&fx.pool, fx.repo_id, fx.user_id).await;
        let files = ["pkg/1.0.0/pkg.bin", "pkg/1.0.0/pkg.pom"];
        for path in files {
            seed(&fx, path, "pkg", "1.0.0").await;
        }
        seed(&fx, "pkg/2.0.0/pkg.bin", "pkg", "2.0.0").await;
        seed(&fx, "other/1.0.0/other.bin", "other", "1.0.0").await;
        let auth = repo_admin(&fx);

        let (blocked_status, blocked_body) = tdh::send(
            app(&fx, Some(auth.clone())),
            json_post(
                format!("/{}/releases/1.0.0/block", fx.repo_key),
                serde_json::json!({ "name": "pkg", "reason": "compromised build" }),
            ),
        )
        .await;
        let mut while_blocked = Vec::new();
        for path in files
            .iter()
            .chain(&["pkg/2.0.0/pkg.bin", "other/1.0.0/other.bin"])
        {
            while_blocked.push(download(&fx, Some(auth.clone()), path).await.0);
        }
        let blocked_audit =
            tdh::audit_row_eventually(&fx.pool, fx.repo_id, "RELEASE_BLOCKED").await;

        let (unblocked_status, unblocked_body) = tdh::send(
            app(&fx, Some(auth.clone())),
            json_post(
                format!("/{}/releases/1.0.0/unblock", fx.repo_key),
                serde_json::json!({ "name": "pkg", "reason": "rebuilt and verified" }),
            ),
        )
        .await;
        let mut after = Vec::new();
        for path in files {
            after.push(download(&fx, Some(auth.clone()), path).await.0);
        }
        let unblocked_audit =
            tdh::audit_row_eventually(&fx.pool, fx.repo_id, "RELEASE_UNBLOCKED").await;
        fx.teardown().await;

        assert_eq!(
            blocked_status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&blocked_body)
        );
        let block: ReleaseBlockResponse = serde_json::from_slice(&blocked_body).unwrap();
        assert_eq!(block.name.as_deref(), Some("pkg"));
        assert_eq!(block.version.as_deref(), Some("1.0.0"));
        assert_eq!(block.blocked_by, Some(fx.user_id));
        assert_eq!(
            while_blocked,
            vec![
                StatusCode::FORBIDDEN,
                StatusCode::FORBIDDEN,
                StatusCode::OK,
                StatusCode::OK
            ]
        );
        assert_eq!(blocked_audit.user_id, Some(fx.user_id));
        assert_eq!(blocked_audit.resource_type, "repository");
        assert_eq!(blocked_audit.details["reason"], "compromised build");
        assert_eq!(blocked_audit.details["actor_tier"], "repository_admin");
        assert_eq!(blocked_audit.details["block_id"], block.id.to_string());

        assert_eq!(
            unblocked_status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&unblocked_body)
        );
        assert_eq!(after, vec![StatusCode::OK, StatusCode::OK]);
        assert_eq!(unblocked_audit.details["reason"], "rebuilt and verified");
        assert_eq!(unblocked_audit.details["block_reason"], "compromised build");
    }

    /// An anonymous download of a blocked release on a public repository is a
    /// 403 that does not carry the reason, and an anonymous caller cannot read
    /// the block. The `GET` follows the quarantine reason gate: an outsider who
    /// sees the repository only because it is public learns that the release is
    /// blocked but not why; a reader holding the repository gets the reason but
    /// not who placed the block; a repository admin gets both.
    #[tokio::test]
    async fn block_reason_and_actor_follow_the_quarantine_disclosure_rule_db() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;
        seed(&fx, "tool/9.9/tool.bin", "tool", "9.9").await;
        let (admin_id, admin_name) = tdh::create_user(&fx.pool).await;
        tdh::grant_repo_admin(&fx.pool, fx.repo_id, admin_id).await;
        let (outsider_id, outsider_name) = tdh::create_user(&fx.pool).await;
        let secret = "incident INC-4812 internal note";
        crate::services::release_block_service::block(
            &fx.pool,
            fx.repo_id,
            &ReleaseCoordinate::Path("tool/9.9/tool.bin".into()),
            secret,
            admin_id,
            &admin_name,
        )
        .await
        .expect("block");

        let (anon_status, anon_body) = download(&fx, None, "tool/9.9/tool.bin").await;
        let (reader_status, reader_body) =
            download(&fx, Some(repo_admin(&fx)), "tool/9.9/tool.bin").await;
        let block_uri = format!("/{}/releases/tool%2F9.9%2Ftool.bin/block", fx.repo_key);
        let read =
            |auth: Option<AuthExtension>| tdh::send(app(&fx, auth), tdh::get(block_uri.clone()));
        let (anon_read, _) = read(None).await;
        let (outsider_status, outsider_body) =
            read(Some(tdh::make_auth(outsider_id, &outsider_name))).await;
        let (member_status, member_body) = read(Some(repo_admin(&fx))).await;
        let (admin_status, admin_body) = read(Some(tdh::make_auth(admin_id, &admin_name))).await;
        tdh::cleanup_user(&fx.pool, outsider_id).await;
        fx.teardown().await;
        tdh::cleanup_user(&fx.pool, admin_id).await;

        assert_eq!(anon_status, StatusCode::FORBIDDEN, "{anon_body}");
        assert!(!anon_body.contains("INC-4812"), "{anon_body}");
        assert!(
            anon_body.contains(crate::services::release_block_service::BLOCKED_DOWNLOAD_MESSAGE),
            "{anon_body}"
        );
        assert_eq!(reader_status, StatusCode::FORBIDDEN);
        assert!(!reader_body.contains("INC-4812"), "{reader_body}");
        assert_eq!(anon_read, StatusCode::UNAUTHORIZED);

        let parse = |status: StatusCode, body: &Bytes| -> ReleaseBlockResponse {
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(body));
            serde_json::from_slice(body).unwrap()
        };
        let outsider = parse(outsider_status, &outsider_body);
        assert_eq!(outsider.path.as_deref(), Some("tool/9.9/tool.bin"));
        assert_eq!(
            outsider.reason, None,
            "public visibility alone must not disclose the reason"
        );
        assert_eq!(outsider.blocked_by, None);
        assert_eq!(outsider.blocked_by_username, None);

        let member = parse(member_status, &member_body);
        assert_eq!(member.reason.as_deref(), Some(secret));
        assert_eq!(
            member.blocked_by, None,
            "the actor is for repository admins only"
        );
        assert_eq!(member.blocked_by_username, None);

        let admin = parse(admin_status, &admin_body);
        assert_eq!(admin.reason.as_deref(), Some(secret));
        assert_eq!(admin.blocked_by, Some(admin_id));
        assert_eq!(
            admin.blocked_by_username.as_deref(),
            Some(admin_name.as_str())
        );
    }

    /// Blocking is repository administration: a member with write access is
    /// refused, the repository admin is not. The reason is required, the
    /// coordinate must exist, a second block is a 409 and unblocking a release
    /// that is not blocked is a 404.
    #[tokio::test]
    async fn block_and_unblock_need_repository_admin_and_a_reason_db() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        seed(&fx, "lib/1.0/lib.bin", "lib", "1.0").await;
        let uri = |action: &str| format!("/{}/releases/1.0/{action}", fx.repo_key);
        let body = serde_json::json!({ "name": "lib", "reason": "bad" });
        let send = |auth: AuthExtension, uri: String, body: serde_json::Value| {
            tdh::send(app(&fx, Some(auth)), json_post(uri, body))
        };

        // A write-capable member who is not a repository admin. A separate
        // principal, because the permission service caches decisions.
        let (member_id, member_name) = tdh::create_user(&fx.pool).await;
        tdh::grant_repo_access(&fx.pool, fx.repo_id, member_id).await;
        let member_auth = tdh::make_auth(member_id, &member_name);
        let (member, _) = send(member_auth.clone(), uri("block"), body.clone()).await;
        // Validation comes first: a blank reason is a 400 even from a caller
        // who could not block.
        let (member_blank, _) = send(
            member_auth,
            uri("block"),
            serde_json::json!({ "name": "lib", "reason": " " }),
        )
        .await;
        tdh::grant_repo_admin(&fx.pool, fx.repo_id, fx.user_id).await;
        let (blank, _) = send(
            repo_admin(&fx),
            uri("block"),
            serde_json::json!({ "name": "lib", "reason": "  " }),
        )
        .await;
        let (missing_reason, _) = send(
            repo_admin(&fx),
            uri("block"),
            serde_json::json!({ "name": "lib" }),
        )
        .await;
        let (unknown, _) = send(
            repo_admin(&fx),
            uri("block"),
            serde_json::json!({ "name": "nope", "reason": "bad" }),
        )
        .await;
        let (not_blocked, _) = send(repo_admin(&fx), uri("unblock"), body.clone()).await;
        let (first, _) = send(repo_admin(&fx), uri("block"), body.clone()).await;
        let (second, _) = send(repo_admin(&fx), uri("block"), body.clone()).await;
        let (no_reason_unblock, _) = send(
            repo_admin(&fx),
            uri("unblock"),
            serde_json::json!({ "name": "lib" }),
        )
        .await;
        let (instance_admin, _) = send(
            tdh::admin_auth(fx.user_id, &fx.username),
            uri("unblock"),
            body.clone(),
        )
        .await;
        let (anon, _) = tdh::send(app(&fx, None), json_post(uri("block"), body)).await;
        fx.teardown().await;
        tdh::cleanup_user(&fx.pool, member_id).await;

        assert_eq!(
            member,
            StatusCode::FORBIDDEN,
            "write access alone must not block"
        );
        assert_eq!(member_blank, StatusCode::BAD_REQUEST);
        assert_eq!(blank, StatusCode::BAD_REQUEST);
        assert_eq!(missing_reason, StatusCode::BAD_REQUEST);
        assert_eq!(unknown, StatusCode::NOT_FOUND);
        assert_eq!(not_blocked, StatusCode::NOT_FOUND);
        assert_eq!(first, StatusCode::CREATED);
        assert_eq!(second, StatusCode::CONFLICT);
        assert_eq!(no_reason_unblock, StatusCode::BAD_REQUEST);
        assert_eq!(instance_admin, StatusCode::OK);
        assert_eq!(anon, StatusCode::UNAUTHORIZED);
    }

    /// The per-member fetch every virtual repository uses
    /// (`proxy_helpers::local_lookup_artifact`) refuses a blocked release with
    /// a 403, which virtual resolution treats as terminal.
    #[tokio::test]
    async fn virtual_member_fetch_of_a_blocked_release_is_refused_db() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        seed(&fx, "svc/4.2/svc.bin", "svc", "4.2").await;
        let location = fx.repo_info("local", None).storage_location();
        let fetch = || {
            crate::api::handlers::proxy_helpers::local_fetch_by_path(
                &fx.pool,
                &fx.state,
                fx.repo_id,
                &location,
                "svc/4.2/svc.bin",
            )
        };
        let before = fetch().await.map(|_| ()).map_err(|r| r.status());
        crate::services::release_block_service::block(
            &fx.pool,
            fx.repo_id,
            &ReleaseCoordinate::Version {
                name: "svc".into(),
                version: "4.2".into(),
            },
            "revoked",
            fx.user_id,
            &fx.username,
        )
        .await
        .expect("block");
        let after = fetch().await.map(|_| ()).map_err(|r| r.status());
        fx.teardown().await;

        assert_eq!(before, Ok(()));
        assert_eq!(after, Err(StatusCode::FORBIDDEN));
    }

    /// Blocking never reopens the coordinate: the bytes stay, so re-publishing
    /// different bytes at the blocked path is still the immutability 409.
    #[tokio::test]
    async fn blocking_never_reopens_the_coordinate_db() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let path = "rel/blocked-target.bin";
        let (first, body) = fx
            .chunked_upload(path, b"the released bytes", serde_json::json!({}), false)
            .await;
        assert_eq!(first, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        crate::services::release_block_service::block(
            &fx.pool,
            fx.repo_id,
            &ReleaseCoordinate::Path(path.into()),
            "revoked",
            fx.user_id,
            &fx.username,
        )
        .await
        .expect("block");
        let (second, body) = fx
            .chunked_upload(path, b"REPLACEMENT bytes", serde_json::json!({}), false)
            .await;
        fx.teardown().await;

        assert_eq!(
            second,
            StatusCode::CONFLICT,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let refusal: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(refusal["code"], crate::error::IMMUTABLE_RELEASE_CODE);
    }

    /// The REST delete of a blocked release is refused with IMMUTABLE_RELEASE
    /// even for an instance admin, who otherwise may retract a release. The
    /// audited override (#10) is what will let it through.
    #[tokio::test]
    async fn rest_delete_of_a_blocked_release_is_refused_for_admins_too_db() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let id = seed(&fx, "gone/1.0/gone.bin", "gone", "1.0").await;
        crate::services::release_block_service::block(
            &fx.pool,
            fx.repo_id,
            &ReleaseCoordinate::Version {
                name: "gone".into(),
                version: "1.0".into(),
            },
            "revoked",
            fx.user_id,
            &fx.username,
        )
        .await
        .expect("block");
        let request = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/{}/artifacts/gone/1.0/gone.bin", fx.repo_key))
            .body(axum::body::Body::empty())
            .unwrap();
        let (status, body) = tdh::send(
            tdh::router_with_auth(
                crate::api::handlers::repositories::router(),
                fx.state.clone(),
                tdh::admin_auth(fx.user_id, &fx.username),
            ),
            request,
        )
        .await;
        let live: bool = sqlx::query_scalar("SELECT NOT is_deleted FROM artifacts WHERE id = $1")
            .bind(id)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let refusal: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(refusal["code"], crate::error::IMMUTABLE_RELEASE_CODE);
        assert!(live, "the refused delete must leave the artifact in place");
    }
}
