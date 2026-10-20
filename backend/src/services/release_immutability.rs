//! Per-repository release immutability policy (#4812).
//!
//! # What the policy adds
//!
//! The always-on rules in
//! [`enforce_path_immutability`](crate::services::artifact_service::enforce_path_immutability)
//! protect a *released* coordinate: a live same-version republish conflicts,
//! and a tombstone of a versioned (or structurally immutable) path refuses
//! different bytes. They stay exactly as they are whatever this policy says.
//!
//! With the policy `on`, every file path in the repository is a release
//! coordinate unless it is exempt, so different bytes can never replace the
//! bytes once stored there, whether the prior row is live or soft-deleted.
//! The policy is matched **per file path**, never per version.
//!
//! # What is exempt
//!
//! * **Structurally mutable paths.** Files a format rewrites in place by
//!   design are never protected: `maven-metadata.xml`, the npm packument, the
//!   APT `dists/` indexes and the like
//!   ([`is_explicitly_mutable_index`](crate::services::cache_classifier::is_explicitly_mutable_index)).
//!   The Maven family instead uses
//!   [`maven_coordinate_is_republishable`](crate::services::cache_classifier::maven_coordinate_is_republishable),
//!   so every file under a `-SNAPSHOT/` version directory stays mutable
//!   (#4476) while an unrecognised file under a release version
//!   stays protected. Conan is still wholly exempt here; bringing its
//!   revision files under the policy is a separate item.
//! * **Exclusion patterns.** Operator-supplied `*` globs, each matched against
//!   every `/`-separated segment of the path (the file name included), case
//!   sensitively. `nightly` exempts `app/nightly/app.tgz`; `*-SNAPSHOT`
//!   exempts `org/x/1.0-SNAPSHOT/x.jar`. The default list is empty, so npm and
//!   PyPI prereleases are protected unless an operator excludes them
//!   (#3484).
//! * **Repositories that store nothing of their own.** Remote and virtual
//!   repositories are never protected. A write addressed at a virtual
//!   repository lands in a hosted member, and the member's policy applies.
//!
//! # Storage
//!
//! Two columns on the `repositories` row, deliberately absent from
//! [`Repository`] (like `format_key`): `release_immutability` (`off`/`on`,
//! default `off`) and `immutability_exclusions` (`TEXT[]`, default empty).
//!
//! # Entry point for enforcement
//!
//! A write or delete path asks [`is_protected`] (or, holding a loaded policy,
//! [`ReleaseImmutabilityPolicy::protects`]) and refuses a protected path.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryFormat, RepositoryType};
use crate::services::audit_export::details::ReleaseImmutabilityChangeAudit;
use crate::services::cache_classifier;
use crate::services::curation::attestation_verify::policy::glob_match;

/// API and audit name of the mode field.
pub const RELEASE_IMMUTABILITY_FIELD: &str = "release_immutability";

/// API and audit name of the exclusion list field.
pub const IMMUTABILITY_EXCLUSIONS_FIELD: &str = "immutability_exclusions";

/// Upper bound on the number of exclusion patterns per repository.
pub const MAX_EXCLUSIONS: usize = 64;

/// Upper bound on one pattern's length.
pub const MAX_EXCLUSION_LEN: usize = 128;

/// Whether a repository's release immutability policy is enforced.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseImmutability {
    /// Only the always-on release rules apply. The default.
    #[default]
    Off,
    /// Every non-exempt file path is immutable once stored.
    On,
}

impl ReleaseImmutability {
    /// The stored and serialized form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// Parse the stored form. Anything unrecognised reads as `on`, so a
    /// corrupt row fails closed.
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "off" => Self::Off,
            _ => Self::On,
        }
    }
}

/// A repository's release immutability policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseImmutabilityPolicy {
    /// Whether the policy is enforced.
    pub release_immutability: ReleaseImmutability,
    /// `*` glob patterns; a path with any segment matching one is exempt.
    pub immutability_exclusions: Vec<String>,
}

impl ReleaseImmutabilityPolicy {
    /// Whether the policy is enforced at all.
    pub fn is_on(&self) -> bool {
        self.release_immutability == ReleaseImmutability::On
    }

    /// Whether an exclusion pattern matches any `/`-separated segment of
    /// `path`.
    pub fn is_excluded(&self, path: &str) -> bool {
        path.split('/').filter(|s| !s.is_empty()).any(|segment| {
            self.immutability_exclusions
                .iter()
                .any(|pattern| glob_match(pattern, segment))
        })
    }

    /// The decision: whether `path` in a repository of `repo_type` and
    /// `format` is protected, so that different bytes must never replace
    /// what is stored there and it must not be deleted without an override.
    pub fn protects(
        &self,
        repo_type: &RepositoryType,
        format: &RepositoryFormat,
        path: &str,
    ) -> bool {
        self.is_on()
            && repo_type.is_hosted()
            && !is_structurally_mutable(format, path)
            && !self.is_excluded(path)
    }

    /// Whether moving from `self` to `next` weakens protection: the policy
    /// was switched off, or an exclusion pattern was added while it is on.
    pub fn is_loosened_by(&self, next: &Self) -> bool {
        if !self.is_on() {
            return false;
        }
        if !next.is_on() {
            return true;
        }
        let before: BTreeSet<&String> = self.immutability_exclusions.iter().collect();
        next.immutability_exclusions
            .iter()
            .any(|p| !before.contains(p))
    }
}

/// The audit record of a policy change from `previous` to `next`.
pub fn change_audit(
    previous: &ReleaseImmutabilityPolicy,
    next: &ReleaseImmutabilityPolicy,
) -> ReleaseImmutabilityChangeAudit {
    ReleaseImmutabilityChangeAudit {
        previous_release_immutability: previous.release_immutability.as_str().to_string(),
        release_immutability: next.release_immutability.as_str().to_string(),
        previous_immutability_exclusions: previous.immutability_exclusions.clone(),
        immutability_exclusions: next.immutability_exclusions.clone(),
        loosened: previous.is_loosened_by(next),
    }
}

/// Whether the format rewrites `path` in place by design, which no policy
/// can make immutable. See the module docs.
pub fn is_structurally_mutable(format: &RepositoryFormat, path: &str) -> bool {
    match format {
        RepositoryFormat::Maven | RepositoryFormat::Gradle | RepositoryFormat::Sbt => {
            cache_classifier::maven_coordinate_is_republishable(path)
        }
        _ => cache_classifier::is_explicitly_mutable_index(format, path),
    }
}

/// Validate operator-supplied exclusion patterns and return them trimmed,
/// deduplicated and sorted.
///
/// A pattern is one path segment: non-empty, at most [`MAX_EXCLUSION_LEN`]
/// characters, no `/` and no control characters, with `*` as the only
/// wildcard. A pattern made only of `*` would exempt everything; switch the
/// policy off instead.
pub fn normalize_exclusions(patterns: &[String]) -> Result<Vec<String>> {
    if patterns.len() > MAX_EXCLUSIONS {
        return Err(AppError::Validation(format!(
            "{IMMUTABILITY_EXCLUSIONS_FIELD} accepts at most {MAX_EXCLUSIONS} patterns"
        )));
    }
    let invalid = |pattern: &str, why: &str| {
        AppError::Validation(format!(
            "{IMMUTABILITY_EXCLUSIONS_FIELD}: '{}' {why}",
            pattern.chars().take(80).collect::<String>()
        ))
    };
    let mut set = BTreeSet::new();
    for raw in patterns {
        let pattern = raw.trim();
        if pattern.is_empty() {
            return Err(invalid(pattern, "must not be empty"));
        }
        if pattern.chars().count() > MAX_EXCLUSION_LEN {
            return Err(invalid(
                pattern,
                &format!("is longer than {MAX_EXCLUSION_LEN} characters"),
            ));
        }
        if pattern.contains('/') {
            return Err(invalid(
                pattern,
                "contains '/'; a pattern matches one path segment",
            ));
        }
        if pattern.chars().any(char::is_control) {
            return Err(invalid(pattern, "contains a control character"));
        }
        if pattern.chars().all(|c| c == '*') {
            return Err(invalid(
                pattern,
                "matches every path; set release_immutability to off instead",
            ));
        }
        set.insert(pattern.to_string());
    }
    Ok(set.into_iter().collect())
}

/// Resolve the policy a create or update asks for, given the stored one
/// (`current`), and validate it against the repository.
///
/// Returns `None` when the request changes nothing. On a remote or virtual
/// repository the default values (`off`, `[]`) are accepted as a no-op, the
/// untouched-form case; anything else is refused, because the policy is never
/// consulted there. The policy cannot be combined with Generic/Mlmodel
/// versioning (`versioning_active`), which replaces the content at a path by
/// design.
pub fn requested_policy(
    current: &ReleaseImmutabilityPolicy,
    mode: Option<ReleaseImmutability>,
    exclusions: Option<&[String]>,
    repo_type: &RepositoryType,
    versioning_active: bool,
) -> Result<Option<ReleaseImmutabilityPolicy>> {
    if mode.is_none() && exclusions.is_none() {
        if current.is_on() && versioning_active {
            return Err(versioning_conflict());
        }
        return Ok(None);
    }
    let next = ReleaseImmutabilityPolicy {
        release_immutability: mode.unwrap_or(current.release_immutability),
        immutability_exclusions: match exclusions {
            Some(list) => normalize_exclusions(list)?,
            None => current.immutability_exclusions.clone(),
        },
    };
    if !repo_type.is_hosted() {
        if next == ReleaseImmutabilityPolicy::default() {
            return Ok(None);
        }
        return Err(AppError::Validation(format!(
            "{RELEASE_IMMUTABILITY_FIELD} and {IMMUTABILITY_EXCLUSIONS_FIELD} are only valid \
             for local and staging repositories; a virtual repository uses the policy of the \
             hosted member it deploys to"
        )));
    }
    if next.is_on() && versioning_active {
        return Err(versioning_conflict());
    }
    Ok((next != *current).then_some(next))
}

fn versioning_conflict() -> AppError {
    AppError::Validation(format!(
        "{RELEASE_IMMUTABILITY_FIELD} cannot be on while versioning_enabled is true: \
         versioning replaces the content at a path, which the policy forbids"
    ))
}

type PolicyRow = (String, Vec<String>);

fn from_row((mode, exclusions): PolicyRow) -> ReleaseImmutabilityPolicy {
    ReleaseImmutabilityPolicy {
        release_immutability: ReleaseImmutability::from_db_str(&mode),
        immutability_exclusions: exclusions,
    }
}

/// Read a repository's policy. A missing repository reads as the default.
pub async fn load<'e, E>(db: E, repository_id: Uuid) -> Result<ReleaseImmutabilityPolicy>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<PolicyRow> = sqlx::query_as(
        "SELECT release_immutability, immutability_exclusions FROM repositories WHERE id = $1",
    )
    .bind(repository_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(row.map(from_row).unwrap_or_default())
}

/// Read the policies of several repositories at once, for the listing.
/// Repositories with the default policy are absent from the map.
pub async fn load_many(
    db: &sqlx::PgPool,
    repository_ids: &[Uuid],
) -> Result<HashMap<Uuid, ReleaseImmutabilityPolicy>> {
    if repository_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, String, Vec<String>)> = sqlx::query_as(
        "SELECT id, release_immutability, immutability_exclusions FROM repositories \
         WHERE id = ANY($1) \
           AND (release_immutability <> 'off' OR cardinality(immutability_exclusions) > 0)",
    )
    .bind(repository_ids)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(rows
        .into_iter()
        .map(|(id, mode, exclusions)| (id, from_row((mode, exclusions))))
        .collect())
}

/// Persist a policy already validated by [`requested_policy`].
pub async fn store<'e, E>(
    db: E,
    repository_id: Uuid,
    policy: &ReleaseImmutabilityPolicy,
) -> Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE repositories SET release_immutability = $2, immutability_exclusions = $3 \
         WHERE id = $1",
    )
    .bind(repository_id)
    .bind(policy.release_immutability.as_str())
    .bind(&policy.immutability_exclusions)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Whether `path` in `repo` is protected by the repository's policy. The one
/// call every write, delete and lifecycle path makes before touching stored
/// bytes.
pub async fn is_protected<'e, E>(db: E, repo: &Repository, path: &str) -> Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(load(db, repo.id)
        .await?
        .protects(&repo.repo_type, &repo.format, path))
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::models::artifact::Artifact;
    use crate::services::artifact_service::ArtifactService;

    fn on(exclusions: &[&str]) -> ReleaseImmutabilityPolicy {
        ReleaseImmutabilityPolicy {
            release_immutability: ReleaseImmutability::On,
            immutability_exclusions: exclusions.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    const LOCAL: RepositoryType = RepositoryType::Local;

    #[test]
    fn default_policy_is_off_and_protects_nothing() {
        let policy = ReleaseImmutabilityPolicy::default();
        assert_eq!(policy.release_immutability, ReleaseImmutability::Off);
        assert!(policy.immutability_exclusions.is_empty());
        assert!(!policy.protects(&LOCAL, &RepositoryFormat::Generic, "app/1.0/app.tgz"));
    }

    #[test]
    fn on_protects_every_generic_path() {
        let policy = on(&[]);
        for path in ["app/1.0/app.tgz", "blob.bin", "a/b/c/d.txt"] {
            assert!(policy.protects(&LOCAL, &RepositoryFormat::Generic, path), "{path}");
        }
    }

    #[test]
    fn staging_is_hosted_and_protected() {
        assert!(on(&[]).protects(
            &RepositoryType::Staging,
            &RepositoryFormat::Generic,
            "app/1.0/app.tgz"
        ));
    }

    #[test]
    fn remote_and_virtual_repositories_are_never_protected() {
        for repo_type in [RepositoryType::Remote, RepositoryType::Virtual] {
            assert!(
                !on(&[]).protects(&repo_type, &RepositoryFormat::Generic, "app/1.0/app.tgz"),
                "{repo_type:?}"
            );
        }
    }

    #[test]
    fn exclusions_match_any_segment() {
        let policy = on(&["latest", "*-SNAPSHOT", "nightly"]);
        let generic = RepositoryFormat::Generic;
        for path in [
            "app/latest/app.tgz",
            "org/x/1.0-SNAPSHOT/x.bin",
            "nightly/app.tgz",
            "app/nightly",
        ] {
            assert!(!policy.protects(&LOCAL, &generic, path), "{path} is excluded");
        }
        for path in ["app/1.0/app.tgz", "app/latest-1/app.tgz", "nightlyish/app.tgz"] {
            assert!(policy.protects(&LOCAL, &generic, path), "{path} is protected");
        }
    }

    #[test]
    fn exclusions_are_case_sensitive() {
        let policy = on(&["nightly"]);
        assert!(policy.protects(&LOCAL, &RepositoryFormat::Generic, "app/Nightly/app.tgz"));
    }

    #[test]
    fn exclusions_do_not_apply_while_off() {
        let policy = ReleaseImmutabilityPolicy {
            release_immutability: ReleaseImmutability::Off,
            immutability_exclusions: strings(&["nightly"]),
        };
        assert!(policy.is_excluded("app/nightly/app.tgz"));
        assert!(!policy.protects(&LOCAL, &RepositoryFormat::Generic, "app/1.0/app.tgz"));
    }

    #[test]
    fn maven_snapshots_stay_mutable_and_unknown_release_files_are_protected() {
        let policy = on(&[]);
        for format in [
            RepositoryFormat::Maven,
            RepositoryFormat::Gradle,
            RepositoryFormat::Sbt,
        ] {
            for path in [
                "com/x/app/1.0-SNAPSHOT/app-1.0-SNAPSHOT.jar",
                "com/x/app/1.0-SNAPSHOT/app-1.0-20260827.132833-10.jar",
                "com/x/app/maven-metadata.xml",
                "com/x/app/maven-metadata.xml.sha1",
            ] {
                assert!(!policy.protects(&LOCAL, &format, path), "{format:?} {path}");
            }
            for path in [
                "com/x/app/1.0/app-1.0.jar",
                "com/x/app/1.0/app-1.0.unknownext",
                "com/x/app/1.0-SNAPSHOT-rc1/app-1.0-SNAPSHOT-rc1.jar",
            ] {
                assert!(policy.protects(&LOCAL, &format, path), "{format:?} {path}");
            }
        }
    }

    #[test]
    fn mutable_index_files_stay_exempt() {
        let policy = on(&[]);
        assert!(!policy.protects(&LOCAL, &RepositoryFormat::Npm, "left-pad"));
        assert!(!policy.protects(
            &LOCAL,
            &RepositoryFormat::Debian,
            "dists/bookworm/main/binary-amd64/Packages"
        ));
        assert!(policy.protects(
            &LOCAL,
            &RepositoryFormat::Debian,
            "pool/main/a/apt/apt_2.5.3_amd64.deb"
        ));
    }

    #[test]
    fn npm_and_pypi_prereleases_are_protected_by_default() {
        let policy = on(&[]);
        assert!(policy.protects(
            &LOCAL,
            &RepositoryFormat::Npm,
            "left-pad/-/left-pad-1.0.0-beta.1.tgz"
        ));
        assert!(policy.protects(
            &LOCAL,
            &RepositoryFormat::Pypi,
            "simple/demo/demo-1.0.0rc1-py3-none-any.whl"
        ));
    }

    #[test]
    fn conan_is_still_exempt_until_its_own_item() {
        assert!(!on(&[]).protects(
            &LOCAL,
            &RepositoryFormat::Conan,
            "v2/conans/zlib/1.3/_/_/revisions/abc/files/conanfile.py"
        ));
    }

    #[test]
    fn loosening_is_switching_off_or_adding_an_exclusion() {
        let off = ReleaseImmutabilityPolicy::default();
        assert!(on(&[]).is_loosened_by(&off));
        assert!(on(&[]).is_loosened_by(&on(&["nightly"])));
        assert!(on(&["a"]).is_loosened_by(&on(&["b"])));
        assert!(!on(&["nightly"]).is_loosened_by(&on(&[])));
        assert!(!on(&["nightly"]).is_loosened_by(&on(&["nightly"])));
        assert!(!off.is_loosened_by(&on(&[])));
        assert!(!off.is_loosened_by(&off));
    }

    #[test]
    fn normalize_trims_dedupes_and_sorts() {
        assert_eq!(
            normalize_exclusions(&strings(&[" nightly ", "latest", "nightly"])).unwrap(),
            strings(&["latest", "nightly"])
        );
        assert!(normalize_exclusions(&[]).unwrap().is_empty());
    }

    #[test]
    fn normalize_rejects_bad_patterns() {
        let too_long = "x".repeat(MAX_EXCLUSION_LEN + 1);
        for bad in ["", "  ", "a/b", "*", "**", "bad\nline", too_long.as_str()] {
            let err = normalize_exclusions(&strings(&[bad])).unwrap_err();
            assert!(
                matches!(err, AppError::Validation(ref m) if m.contains(IMMUTABILITY_EXCLUSIONS_FIELD)),
                "{bad:?}: {err:?}"
            );
        }
        let many: Vec<String> = (0..=MAX_EXCLUSIONS).map(|i| format!("p{i}")).collect();
        assert!(normalize_exclusions(&many).is_err());
    }

    #[test]
    fn mode_round_trips_and_unknown_fails_closed() {
        for mode in [ReleaseImmutability::Off, ReleaseImmutability::On] {
            assert_eq!(ReleaseImmutability::from_db_str(mode.as_str()), mode);
            assert_eq!(
                serde_json::to_value(mode).unwrap(),
                serde_json::json!(mode.as_str())
            );
        }
        assert_eq!(ReleaseImmutability::from_db_str("garbage"), ReleaseImmutability::On);
        assert!(serde_json::from_value::<ReleaseImmutability>(serde_json::json!("maybe")).is_err());
    }

    #[test]
    fn requested_policy_omitted_fields_change_nothing() {
        let current = on(&["nightly"]);
        assert_eq!(
            requested_policy(&current, None, None, &LOCAL, false).unwrap(),
            None
        );
        assert_eq!(
            requested_policy(&current, Some(ReleaseImmutability::On), None, &LOCAL, false)
                .unwrap(),
            None
        );
    }

    #[test]
    fn requested_policy_merges_onto_current() {
        let current = on(&["nightly"]);
        assert_eq!(
            requested_policy(&current, Some(ReleaseImmutability::Off), None, &LOCAL, false)
                .unwrap(),
            Some(ReleaseImmutabilityPolicy {
                release_immutability: ReleaseImmutability::Off,
                immutability_exclusions: strings(&["nightly"]),
            })
        );
        let empty: &[String] = &[];
        assert_eq!(
            requested_policy(&current, None, Some(empty), &LOCAL, false).unwrap(),
            Some(on(&[]))
        );
    }

    #[test]
    fn requested_policy_on_proxying_types_accepts_only_defaults() {
        let off = ReleaseImmutabilityPolicy::default();
        let empty: &[String] = &[];
        for repo_type in [RepositoryType::Remote, RepositoryType::Virtual] {
            assert_eq!(
                requested_policy(
                    &off,
                    Some(ReleaseImmutability::Off),
                    Some(empty),
                    &repo_type,
                    false
                )
                .unwrap(),
                None
            );
            let err = requested_policy(&off, Some(ReleaseImmutability::On), None, &repo_type, false)
                .unwrap_err();
            assert!(matches!(err, AppError::Validation(ref m) if m.contains("hosted member")));
            let list = strings(&["nightly"]);
            assert!(requested_policy(&off, None, Some(&list), &repo_type, false).is_err());
        }
    }

    #[test]
    fn requested_policy_refuses_versioning_combination() {
        let off = ReleaseImmutabilityPolicy::default();
        let err = requested_policy(&off, Some(ReleaseImmutability::On), None, &LOCAL, true)
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("versioning_enabled")));
        // Turning versioning on under an enforced policy is refused too.
        assert!(requested_policy(&on(&[]), None, None, &LOCAL, true).is_err());
        // Versioning with the policy off is today's behaviour.
        assert_eq!(requested_policy(&off, None, None, &LOCAL, true).unwrap(), None);
    }

    #[tokio::test]
    async fn store_load_and_is_protected_round_trip_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;
        let (repo_id, _key, dir) = tdh::create_repo(&pool, "local", "generic").await;

        assert_eq!(
            load(&pool, repo_id).await.unwrap(),
            ReleaseImmutabilityPolicy::default(),
            "a new repository defaults to off with no exclusions"
        );
        assert!(load_many(&pool, &[repo_id]).await.unwrap().is_empty());

        let policy = on(&["nightly"]);
        store(&pool, repo_id, &policy).await.unwrap();
        assert_eq!(load(&pool, repo_id).await.unwrap(), policy);
        assert_eq!(
            load_many(&pool, &[repo_id]).await.unwrap().get(&repo_id),
            Some(&policy)
        );

        let repo = crate::services::repository_service::RepositoryService::new(pool.clone())
            .get_by_id(repo_id)
            .await
            .unwrap();
        assert!(is_protected(&pool, &repo, "app/1.0/app.tgz").await.unwrap());
        assert!(!is_protected(&pool, &repo, "app/nightly/app.tgz").await.unwrap());

        let rejected = sqlx::query(
            "UPDATE repositories SET release_immutability = 'sometimes' WHERE id = $1",
        )
        .bind(repo_id)
        .execute(&pool)
        .await;
        assert!(rejected.is_err(), "the CHECK constraint refuses unknown modes");

        assert_eq!(
            load(&pool, Uuid::new_v4()).await.unwrap(),
            ReleaseImmutabilityPolicy::default()
        );
        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(dir);
    }

    // -----------------------------------------------------------------------
    // The upload oracle (`enforce_path_immutability`) under the policy
    // -----------------------------------------------------------------------

    /// One hosted repository of a given format plus an upload service on it.
    struct Fixture {
        pool: sqlx::PgPool,
        user_id: Uuid,
        repo_id: Uuid,
        dir: std::path::PathBuf,
        svc: ArtifactService,
    }

    impl Fixture {
        async fn new(format: &str) -> Option<Self> {
            let pool = tdh::try_pool().await?;
            let (user_id, _) = tdh::create_user(&pool).await;
            let (repo_id, _key, dir) = tdh::create_repo(&pool, "local", format).await;
            let storage: std::sync::Arc<dyn crate::storage::StorageBackend> = std::sync::Arc::new(
                crate::storage::filesystem::FilesystemStorage::new(dir.clone()),
            );
            let svc = ArtifactService::new(pool.clone(), storage);
            Some(Self {
                pool,
                user_id,
                repo_id,
                dir,
                svc,
            })
        }

        async fn set(&self, policy: &ReleaseImmutabilityPolicy) {
            store(&self.pool, self.repo_id, policy).await.unwrap();
        }

        async fn upload(&self, path: &str, version: Option<&str>, bytes: &'static [u8]) -> Result<Artifact> {
            let name = path.rsplit('/').next().unwrap_or(path);
            self.svc
                .upload_with_sync_options(
                    self.repo_id,
                    path,
                    name,
                    version,
                    "application/octet-stream",
                    bytes::Bytes::from_static(bytes),
                    Some(self.user_id),
                    false,
                )
                .await
        }

        /// Upload `path`, soft-delete it, then upload DIFFERENT bytes there:
        /// the delete-then-reupload content swap. Returns the second upload.
        async fn swap(&self, path: &str, version: Option<&str>) -> Result<Artifact> {
            self.upload(path, version, b"original-bytes")
                .await
                .expect("first upload of a fresh path must succeed");
            sqlx::query(
                "UPDATE artifacts SET is_deleted = true WHERE repository_id = $1 AND path = $2",
            )
            .bind(self.repo_id)
            .bind(path)
            .execute(&self.pool)
            .await
            .unwrap();
            self.upload(path, version, b"DIFFERENT-bytes").await
        }

        async fn done(self) {
            tdh::cleanup(&self.pool, self.repo_id, self.user_id).await;
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The refusal is asserted by HTTP status only, so this holds both for
    /// today's `Conflict` and for the stable immutability error code.
    fn assert_refused(result: Result<Artifact>, what: &str) {
        use axum::response::IntoResponse;
        match result {
            Err(e) => assert_eq!(
                e.into_response().status(),
                axum::http::StatusCode::CONFLICT,
                "{what}: the immutability refusal must be a 409"
            ),
            Ok(a) => panic!("{what}: expected a 409, the upload of {} succeeded", a.path),
        }
    }

    /// The headline gap: a version-less Generic blob is freely replaceable
    /// after a delete today (the backstop only covers released coordinates),
    /// and stays so with the policy off. With it on, the swap is refused.
    #[tokio::test]
    async fn versionless_generic_swap_is_refused_only_when_on_db() {
        let Some(fx) = Fixture::new("generic").await else {
            return;
        };
        fx.swap("blobs/off.bin", None)
            .await
            .expect("policy off: today's behaviour, the swap succeeds");

        fx.set(&on(&[])).await;
        assert_refused(fx.swap("blobs/on.bin", None).await, "policy on");

        // Identical bytes over the tombstone are an idempotent undelete.
        fx.upload("blobs/on.bin", None, b"original-bytes")
            .await
            .expect("identical bytes over a protected tombstone must succeed");
        fx.done().await;
    }

    #[tokio::test]
    async fn excluded_segment_stays_replaceable_when_on_db() {
        let Some(fx) = Fixture::new("generic").await else {
            return;
        };
        fx.set(&on(&["nightly", "latest", "*-SNAPSHOT"])).await;
        for path in [
            "app/nightly/app.tgz",
            "app/latest/app.tgz",
            "app/2.0-SNAPSHOT/app.tgz",
        ] {
            fx.swap(path, None)
                .await
                .unwrap_or_else(|e| panic!("{path} is excluded and must stay replaceable: {e:?}"));
        }
        assert_refused(fx.swap("app/2.0/app.tgz", None).await, "non-excluded path");
        fx.done().await;
    }

    /// The Maven classifier treats an unrecognised file under a RELEASE
    /// version as mutable, so today it is replaceable after a delete. The
    /// policy uses the republishable test instead and protects it, while a
    /// `-SNAPSHOT/` file stays replaceable.
    #[tokio::test]
    async fn maven_release_file_is_protected_and_snapshot_is_not_db() {
        let Some(fx) = Fixture::new("maven").await else {
            return;
        };
        let release = "com/x/app/1.0/app-1.0.unknownext";
        fx.swap(release, Some("1.0"))
            .await
            .expect("policy off: today's behaviour, the swap succeeds");

        fx.set(&on(&[])).await;
        assert_refused(
            fx.swap("com/x/app/1.1/app-1.1.unknownext", Some("1.1")).await,
            "maven release file, policy on",
        );
        fx.swap("com/x/app/1.2-SNAPSHOT/app-1.2-SNAPSHOT.jar", Some("1.2-SNAPSHOT"))
            .await
            .expect("a -SNAPSHOT/ file stays replaceable with the policy on");
        fx.done().await;
    }

    #[tokio::test]
    async fn npm_packument_stays_replaceable_when_on_db() {
        let Some(fx) = Fixture::new("npm").await else {
            return;
        };
        fx.set(&on(&[])).await;
        fx.swap("left-pad", None)
            .await
            .expect("the packument is rewritten in place by design");
        fx.done().await;
    }

    /// Versioning and the policy cannot be combined through the API. A row
    /// carrying both anyway (set directly in SQL) is protected: the policy
    /// wins over versioning's append-a-revision overwrite.
    #[tokio::test]
    async fn policy_wins_over_versioning_db() {
        let Some(fx) = Fixture::new("generic").await else {
            return;
        };
        sqlx::query("UPDATE repositories SET versioning_enabled = true WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        fx.upload("v/app.bin", Some("1"), b"original-bytes").await.unwrap();
        fx.upload("v/app.bin", Some("1"), b"DIFFERENT-bytes")
            .await
            .expect("policy off: versioning appends a revision");

        fx.set(&on(&[])).await;
        fx.upload("w/app.bin", Some("1"), b"original-bytes").await.unwrap();
        assert_refused(
            fx.upload("w/app.bin", Some("1"), b"DIFFERENT-bytes").await,
            "versioning under policy on",
        );
        fx.done().await;
    }
}
