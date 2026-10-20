//! The release blocklist (upstream #4812, P2).
//!
//! A block revokes a release without deleting or overwriting it: its bytes and
//! artifact rows stay in place for forensics, and the immutability backstops
//! keep comparing a re-publish against them, but nothing can download it.
//!
//! Blocks live in `release_blocks` (migration 295), not in
//! `artifacts.quarantine_status`. Quarantine is per file and scan-driven: a
//! re-scan, a quarantine release and a trash restore all rewrite that column.
//! None of them touches this table, so none of them can lift a block. Only
//! [`unblock`] does.
//!
//! The download gate ([`enforce_download_allowed`]) runs from the two shared
//! download choke points, `quarantine_service::enforce_download_gate` and
//! `proxy_helpers::local_lookup_artifact`, so every format that routes through
//! either is covered without per-handler code.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// The refusal a download of a blocked release gets, for every caller.
///
/// Deliberately says nothing about WHY the release was blocked. The format
/// download routes are readable anonymously on a public repository, so the
/// reason (an incident note) must not appear here; this is the rule quarantine
/// follows for `rejected` (upstream #2912). Authenticated readers get the
/// reason from `GET /api/v1/repositories/{key}/releases/{coordinate}/block`.
pub const BLOCKED_DOWNLOAD_MESSAGE: &str =
    "This release has been blocked by a repository administrator";

/// Longest block or unblock reason accepted, in characters.
pub const MAX_REASON_CHARS: usize = 4096;

/// Block modes. Only `block` exists today; the soft "yank" mode (#14) widens
/// `release_blocks_mode_check` and adds a variant here.
pub const MODE_BLOCK: &str = "block";

/// The SQL condition matching a `release_blocks b` row to an `artifacts a`
/// row: the same repository and either the same `(name, version)` or, for a
/// path block, the same path.
const BLOCK_MATCHES_ARTIFACT_SQL: &str = "b.repository_id = a.repository_id \
     AND ((b.path IS NULL AND b.name = a.name AND b.version = a.version) \
          OR b.path = a.path)";

/// What a block covers: every file of one version, or one file by path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseCoordinate {
    /// Every artifact with this `name` and `version` in the repository.
    Version { name: String, version: String },
    /// The single artifact stored at this path, for files with no version.
    Path(String),
}

impl ReleaseCoordinate {
    /// Build a coordinate from the API's `{coordinate}` path segment and the
    /// optional package `name`. With a name, the segment is the version; without
    /// one, it is the file path.
    pub fn parse(coordinate: &str, name: Option<&str>) -> Result<Self> {
        let coordinate = coordinate.trim();
        if coordinate.is_empty() {
            return Err(AppError::Validation(
                "A release coordinate is required".to_string(),
            ));
        }
        match name.map(str::trim) {
            Some("") => Err(AppError::Validation(
                "name must not be empty when given".to_string(),
            )),
            Some(name) => Ok(Self::Version {
                name: name.to_string(),
                version: coordinate.to_string(),
            }),
            None => Ok(Self::Path(coordinate.trim_start_matches('/').to_string())),
        }
    }

    /// `(name, version, path)` as stored in `release_blocks`.
    fn columns(&self) -> (Option<&str>, Option<&str>, Option<&str>) {
        match self {
            Self::Version { name, version } => (Some(name), Some(version), None),
            Self::Path(path) => (None, None, Some(path)),
        }
    }
}

/// One row of `release_blocks`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReleaseBlock {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub name: Option<String>,
    pub version: Option<String>,
    pub path: Option<String>,
    pub mode: String,
    pub reason: String,
    pub actor_id: Option<Uuid>,
    pub actor_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Trim and check a block or unblock reason: required, at most
/// [`MAX_REASON_CHARS`].
pub fn validate_reason(reason: &str) -> Result<&str> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AppError::Validation("A reason is required".to_string()));
    }
    if reason.chars().count() > MAX_REASON_CHARS {
        return Err(AppError::Validation(format!(
            "reason must be at most {MAX_REASON_CHARS} characters"
        )));
    }
    Ok(reason)
}

/// Map "is this artifact blocked" onto the download gate's result.
pub fn download_gate_result(blocked: bool) -> Result<()> {
    if blocked {
        Err(AppError::Authorization(
            BLOCKED_DOWNLOAD_MESSAGE.to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Map "is this artifact blocked" onto the delete guard's result.
///
/// Deleting a blocked release would let its coordinate be purged and re-used,
/// which is exactly what a block must never do. It applies to admins too:
/// lifting it is the audited override's job (#10), which has not landed, so
/// until then the delete is refused outright.
pub fn delete_guard_result(blocked: bool) -> Result<()> {
    if blocked {
        Err(AppError::Immutable(
            "Cannot delete a blocked release; unblock it first".to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Whether the artifact `artifact_id` (live or in the trash) belongs to a
/// blocked release. An unknown id is not blocked.
pub async fn is_artifact_blocked(db: &PgPool, artifact_id: Uuid) -> Result<bool> {
    let sql = format!(
        "SELECT EXISTS (SELECT 1 FROM artifacts a JOIN release_blocks b ON {BLOCK_MATCHES_ARTIFACT_SQL} \
         WHERE a.id = $1)"
    );
    sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(&*sql))
        .bind(artifact_id)
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
}

/// The release-blocklist download gate: 403 with [`BLOCKED_DOWNLOAD_MESSAGE`]
/// when `artifact_id` belongs to a blocked release.
pub async fn enforce_download_allowed(db: &PgPool, artifact_id: Uuid) -> Result<()> {
    download_gate_result(is_artifact_blocked(db, artifact_id).await?)
}

/// Refuse to delete (or purge) `artifact_id` while its release is blocked.
pub async fn refuse_delete_if_blocked(db: &PgPool, artifact_id: Uuid) -> Result<()> {
    delete_guard_result(is_artifact_blocked(db, artifact_id).await?)
}

/// Whether any artifact row, live or in the trash, sits at `coordinate`.
async fn coordinate_exists(
    db: &PgPool,
    repository_id: Uuid,
    coordinate: &ReleaseCoordinate,
) -> Result<bool> {
    let query = match coordinate {
        ReleaseCoordinate::Version { name, version } => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM artifacts \
             WHERE repository_id = $1 AND name = $2 AND version = $3)",
        )
        .bind(repository_id)
        .bind(name)
        .bind(version),
        ReleaseCoordinate::Path(path) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM artifacts WHERE repository_id = $1 AND path = $2)",
        )
        .bind(repository_id)
        .bind(path),
    };
    query
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
}

const BLOCK_COLUMNS_SQL: &str =
    "id, repository_id, name, version, path, mode, reason, actor_id, actor_name, created_at";

/// The SQL condition selecting the `release_blocks` row for a coordinate,
/// with `$1` = repository, `$2` = name, `$3` = version, `$4` = path.
const COORDINATE_ROW_SQL: &str = "repository_id = $1 \
     AND name IS NOT DISTINCT FROM $2 AND version IS NOT DISTINCT FROM $3 \
     AND path IS NOT DISTINCT FROM $4";

/// Block `coordinate` in `repository_id`.
///
/// The coordinate must name at least one artifact (a trashed one counts), so a
/// typo is a 404 rather than a block that matches nothing. Blocking a release
/// that is already blocked is a 409; the original block and its reason stand.
pub async fn block(
    db: &PgPool,
    repository_id: Uuid,
    coordinate: &ReleaseCoordinate,
    reason: &str,
    actor_id: Uuid,
    actor_name: &str,
) -> Result<ReleaseBlock> {
    let reason = validate_reason(reason)?;
    if !coordinate_exists(db, repository_id, coordinate).await? {
        return Err(AppError::NotFound(
            "No release matches this coordinate".to_string(),
        ));
    }
    let (name, version, path) = coordinate.columns();
    let sql = format!(
        "INSERT INTO release_blocks \
             (repository_id, name, version, path, mode, reason, actor_id, actor_name) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT DO NOTHING \
         RETURNING {BLOCK_COLUMNS_SQL}"
    );
    sqlx::query_as::<_, ReleaseBlock>(sqlx::AssertSqlSafe(&*sql))
        .bind(repository_id)
        .bind(name)
        .bind(version)
        .bind(path)
        .bind(MODE_BLOCK)
        .bind(reason)
        .bind(actor_id)
        .bind(actor_name)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Conflict("This release is already blocked".to_string()))
}

/// Lift the block on `coordinate`, returning the block that was removed.
/// 404 when the coordinate is not blocked.
pub async fn unblock(
    db: &PgPool,
    repository_id: Uuid,
    coordinate: &ReleaseCoordinate,
) -> Result<ReleaseBlock> {
    let (name, version, path) = coordinate.columns();
    let sql = format!(
        "DELETE FROM release_blocks WHERE {COORDINATE_ROW_SQL} RETURNING {BLOCK_COLUMNS_SQL}"
    );
    sqlx::query_as::<_, ReleaseBlock>(sqlx::AssertSqlSafe(&*sql))
        .bind(repository_id)
        .bind(name)
        .bind(version)
        .bind(path)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("This release is not blocked".to_string()))
}

/// The block on `coordinate`, if there is one.
pub async fn get(
    db: &PgPool,
    repository_id: Uuid,
    coordinate: &ReleaseCoordinate,
) -> Result<Option<ReleaseBlock>> {
    let (name, version, path) = coordinate.columns();
    let sql = format!("SELECT {BLOCK_COLUMNS_SQL} FROM release_blocks WHERE {COORDINATE_ROW_SQL}");
    sqlx::query_as::<_, ReleaseBlock>(sqlx::AssertSqlSafe(&*sql))
        .bind(repository_id)
        .bind(name)
        .bind(version)
        .bind(path)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    #[test]
    fn parse_with_name_is_a_version_coordinate() {
        assert_eq!(
            ReleaseCoordinate::parse(" 1.2.3 ", Some(" @scope/pkg ")).unwrap(),
            ReleaseCoordinate::Version {
                name: "@scope/pkg".into(),
                version: "1.2.3".into(),
            }
        );
    }

    #[test]
    fn parse_without_name_is_a_path_coordinate() {
        assert_eq!(
            ReleaseCoordinate::parse("/files/tool.bin", None).unwrap(),
            ReleaseCoordinate::Path("files/tool.bin".into())
        );
    }

    #[test]
    fn parse_refuses_an_empty_coordinate_or_name() {
        assert!(matches!(
            ReleaseCoordinate::parse("  ", None),
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            ReleaseCoordinate::parse("1.0.0", Some(" ")),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn reason_is_required_and_bounded() {
        assert_eq!(validate_reason("  leaked key  ").unwrap(), "leaked key");
        assert!(matches!(validate_reason(" "), Err(AppError::Validation(_))));
        let long = "x".repeat(MAX_REASON_CHARS + 1);
        assert!(matches!(
            validate_reason(&long),
            Err(AppError::Validation(_))
        ));
        assert!(validate_reason(&long[1..]).is_ok());
    }

    #[test]
    fn download_gate_is_a_generic_403() {
        assert!(download_gate_result(false).is_ok());
        match download_gate_result(true) {
            Err(AppError::Authorization(msg)) => assert_eq!(msg, BLOCKED_DOWNLOAD_MESSAGE),
            other => panic!("expected a 403, got {other:?}"),
        }
    }

    #[test]
    fn delete_guard_is_immutable_release() {
        assert!(delete_guard_result(false).is_ok());
        assert!(matches!(
            delete_guard_result(true),
            Err(AppError::Immutable(_))
        ));
    }

    /// Insert an artifact row (no stored bytes) and return its id.
    async fn insert_row(
        fx: &tdh::Fixture,
        path: &str,
        name: &str,
        version: Option<&str>,
        deleted: bool,
    ) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key, is_deleted) \
             VALUES ($1, $2, $3, $4, 1, repeat('a', 64), 'application/octet-stream', $2, $5) \
             RETURNING id",
        )
        .bind(fx.repo_id)
        .bind(path)
        .bind(name)
        .bind(version)
        .bind(deleted)
        .fetch_one(&fx.pool)
        .await
        .expect("insert artifact")
    }

    fn version(name: &str, version: &str) -> ReleaseCoordinate {
        ReleaseCoordinate::Version {
            name: name.into(),
            version: version.into(),
        }
    }

    /// A version block covers every file of that version and nothing else:
    /// not another version of the package, not the same version of another
    /// package. Unblocking restores all of them.
    #[tokio::test]
    async fn version_block_covers_every_file_of_the_version_only_db() {
        let Some(fx) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };
        let wheel = insert_row(
            &fx,
            "pkg/1.0/pkg-1.0-py3-none-any.whl",
            "pkg",
            Some("1.0"),
            false,
        )
        .await;
        let sdist = insert_row(&fx, "pkg/1.0/pkg-1.0.tar.gz", "pkg", Some("1.0"), false).await;
        let newer = insert_row(&fx, "pkg/1.1/pkg-1.1.tar.gz", "pkg", Some("1.1"), false).await;
        let other = insert_row(
            &fx,
            "other/1.0/other-1.0.tar.gz",
            "other",
            Some("1.0"),
            false,
        )
        .await;

        let block = block(
            &fx.pool,
            fx.repo_id,
            &version("pkg", "1.0"),
            " leaked token ",
            fx.user_id,
            &fx.username,
        )
        .await
        .expect("block");
        let mut blocked = Vec::new();
        for id in [wheel, sdist, newer, other] {
            blocked.push(is_artifact_blocked(&fx.pool, id).await.unwrap());
        }
        let gate = enforce_download_allowed(&fx.pool, sdist).await;
        let read = get(&fx.pool, fx.repo_id, &version("pkg", "1.0"))
            .await
            .unwrap();
        let lifted = unblock(&fx.pool, fx.repo_id, &version("pkg", "1.0"))
            .await
            .expect("unblock");
        let after = is_artifact_blocked(&fx.pool, wheel).await.unwrap();
        let again = unblock(&fx.pool, fx.repo_id, &version("pkg", "1.0")).await;
        fx.teardown().await;

        assert_eq!(block.reason, "leaked token", "the reason is stored trimmed");
        assert_eq!(block.mode, MODE_BLOCK);
        assert_eq!(block.actor_id, Some(fx.user_id));
        assert_eq!(blocked, vec![true, true, false, false]);
        assert!(matches!(gate, Err(AppError::Authorization(_))), "{gate:?}");
        assert_eq!(read.map(|b| b.id), Some(block.id));
        assert_eq!(lifted.id, block.id);
        assert!(!after, "unblock restores every file of the version");
        assert!(matches!(again, Err(AppError::NotFound(_))), "{again:?}");
    }

    /// A path block covers one file; a coordinate matching no artifact is a
    /// 404; blocking twice is a 409 and keeps the first block.
    #[tokio::test]
    async fn path_block_unknown_coordinate_and_double_block_db() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let file = insert_row(&fx, "tools/tool.bin", "tool.bin", None, false).await;
        let sibling = insert_row(&fx, "tools/other.bin", "other.bin", None, false).await;
        let path = ReleaseCoordinate::Path("tools/tool.bin".into());

        let first = block(
            &fx.pool,
            fx.repo_id,
            &path,
            "first",
            fx.user_id,
            &fx.username,
        )
        .await;
        let second = block(
            &fx.pool,
            fx.repo_id,
            &path,
            "second",
            fx.user_id,
            &fx.username,
        )
        .await;
        let missing = block(
            &fx.pool,
            fx.repo_id,
            &ReleaseCoordinate::Path("tools/nope.bin".into()),
            "typo",
            fx.user_id,
            &fx.username,
        )
        .await;
        let blank = block(&fx.pool, fx.repo_id, &path, "  ", fx.user_id, &fx.username).await;
        let file_blocked = is_artifact_blocked(&fx.pool, file).await.unwrap();
        let sibling_blocked = is_artifact_blocked(&fx.pool, sibling).await.unwrap();
        let kept = get(&fx.pool, fx.repo_id, &path).await.unwrap();
        fx.teardown().await;

        assert!(first.is_ok(), "{first:?}");
        assert!(matches!(second, Err(AppError::Conflict(_))), "{second:?}");
        assert!(matches!(missing, Err(AppError::NotFound(_))), "{missing:?}");
        assert!(matches!(blank, Err(AppError::Validation(_))), "{blank:?}");
        assert!(file_blocked);
        assert!(!sibling_blocked, "a path block covers one file");
        assert_eq!(kept.map(|b| b.reason).as_deref(), Some("first"));
    }

    /// The shared download gate refuses a blocked release with the block's 403
    /// even while the file is also quarantined (which alone would be a 409),
    /// and a quarantine release does not lift the block.
    #[tokio::test]
    async fn download_gate_puts_the_block_first_and_quarantine_release_keeps_it_db() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let id = insert_row(&fx, "app/2.0/app.bin", "app", Some("2.0"), false).await;
        sqlx::query("UPDATE artifacts SET quarantine_status = 'quarantined' WHERE id = $1")
            .bind(id)
            .execute(&fx.pool)
            .await
            .unwrap();
        block(
            &fx.pool,
            fx.repo_id,
            &version("app", "2.0"),
            "incident",
            fx.user_id,
            &fx.username,
        )
        .await
        .expect("block");

        let held = crate::services::quarantine_service::enforce_download_gate(&fx.pool, id).await;
        crate::services::quarantine_service::transition(
            &fx.pool,
            id,
            crate::services::quarantine_service::QuarantineState::Released,
            None,
        )
        .await
        .expect("quarantine release");
        let released =
            crate::services::quarantine_service::enforce_download_gate(&fx.pool, id).await;
        fx.teardown().await;

        assert!(
            matches!(held, Err(AppError::Authorization(ref m)) if m == BLOCKED_DOWNLOAD_MESSAGE),
            "{held:?}"
        );
        assert!(
            matches!(released, Err(AppError::Authorization(ref m)) if m == BLOCKED_DOWNLOAD_MESSAGE),
            "a quarantine release must not lift the block: {released:?}"
        );
    }

    /// A trashed file of a blocked release can be blocked, stays blocked when
    /// restored, and can be neither deleted again nor purged.
    #[tokio::test]
    async fn trash_restore_keeps_the_block_and_delete_and_purge_are_refused_db() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let repo = fx.repo_info("local", None);
        let storage_key = format!("rb-test/{}.bin", Uuid::new_v4());
        let id = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            &storage_key,
            "lib/3.0/lib.bin",
            "lib",
            "3.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"lib-3.0"),
            fx.user_id,
        )
        .await;
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(id)
            .execute(&fx.pool)
            .await
            .unwrap();
        block(
            &fx.pool,
            fx.repo_id,
            &version("lib", "3.0"),
            "revoked",
            fx.user_id,
            &fx.username,
        )
        .await
        .expect("a trashed release can be blocked");

        let trash = crate::api::handlers::trash::trash_service(&fx.state);
        let purge = trash.purge(id).await;
        let restore = trash.restore(id).await;
        let gate = enforce_download_allowed(&fx.pool, id).await;
        let delete = fx
            .state
            .create_artifact_service(fx.state.storage_for_repo(&repo.storage_location()).unwrap())
            .delete(id)
            .await;
        let live: bool = sqlx::query_scalar("SELECT NOT is_deleted FROM artifacts WHERE id = $1")
            .bind(id)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        fx.teardown().await;

        assert!(matches!(purge, Err(AppError::Immutable(_))), "{purge:?}");
        assert!(restore.is_ok(), "{restore:?}");
        assert!(
            matches!(gate, Err(AppError::Authorization(_))),
            "a trash restore must not lift the block: {gate:?}"
        );
        assert!(matches!(delete, Err(AppError::Immutable(_))), "{delete:?}");
        assert!(live, "the refused delete left the restored row live");
    }
}
