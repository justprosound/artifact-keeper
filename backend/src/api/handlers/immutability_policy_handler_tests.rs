//! #6: the release immutability policy through the native format handlers,
//! which insert their own artifact rows and reach the policy only through
//! [`purge_tombstone_checked`](super::purge_tombstone_checked).
//!
//! Each case is the delete-then-reupload content swap driven through the
//! format's real router: publish, soft-delete the row, publish different
//! bytes at the same path.

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum::Router;
    use bytes::Bytes;

    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::SharedState;
    use crate::services::release_immutability::{
        self, ReleaseImmutability, ReleaseImmutabilityPolicy,
    };

    /// Builds one publish request: PUT `uri` with `body`.
    type Publish = fn(String, Bytes) -> axum::http::Request<axum::body::Body>;

    async fn set_policy(fx: &tdh::Fixture, mode: ReleaseImmutability) {
        let policy = ReleaseImmutabilityPolicy {
            release_immutability: mode,
            immutability_exclusions: Vec::new(),
        };
        release_immutability::store(&fx.pool, fx.repo_id, &policy)
            .await
            .unwrap();
    }

    /// Publish `first`, soft-delete the row whose path ends in `stored_suffix`,
    /// then publish `second` to the same URI. Returns the second publish's
    /// status and error `code`.
    async fn swap(
        fx: &tdh::Fixture,
        router: fn() -> Router<SharedState>,
        publish: Publish,
        uri: &str,
        stored_suffix: &str,
        (first, second): (Bytes, Bytes),
    ) -> (StatusCode, Option<String>) {
        let uri = format!("/{}/{uri}", fx.repo_key);
        let (status, body) =
            tdh::send(fx.router_with_auth(router()), publish(uri.clone(), first)).await;
        assert!(
            status.is_success(),
            "first publish of {uri}: {status} {}",
            String::from_utf8_lossy(&body)
        );
        let deleted = sqlx::query(
            "UPDATE artifacts SET is_deleted = true \
             WHERE repository_id = $1 AND path LIKE '%' || $2 AND is_deleted = false",
        )
        .bind(fx.repo_id)
        .bind(stored_suffix)
        .execute(&fx.pool)
        .await
        .unwrap()
        .rows_affected();
        assert_eq!(deleted, 1, "exactly one row of {uri} soft-deleted");
        let (status, body) = tdh::send(fx.router_with_auth(router()), publish(uri, second)).await;
        let code = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["code"].as_str().map(str::to_string));
        (status, code)
    }

    fn assert_immutable((status, code): (StatusCode, Option<String>), what: &str) {
        assert_eq!(status, StatusCode::CONFLICT, "{what}");
        assert_eq!(code.as_deref(), Some("IMMUTABLE_RELEASE"), "{what}");
    }

    /// A file the Maven classifier does not recognise (here a CycloneDX SBOM
    /// attached to a release) is a mutable index to the always-on tombstone
    /// check, so today its bytes can be swapped after a delete. The policy
    /// protects it, and a `-SNAPSHOT/` file stays replaceable.
    #[tokio::test]
    async fn maven_handler_policy_protects_unrecognised_release_files_db() {
        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let router = crate::api::handlers::maven::router;
        let bytes = || {
            (
                Bytes::from_static(b"sbom-one"),
                Bytes::from_static(b"sbom-two"),
            )
        };
        let sbom = |v: &str| format!("com/example/pol/demo/{v}/demo-{v}-cyclonedx.json");

        let off = swap(
            &fx,
            router,
            tdh::put,
            &sbom("1.0.0"),
            "demo-1.0.0-cyclonedx.json",
            bytes(),
        )
        .await;
        assert_eq!(
            off.0,
            StatusCode::CREATED,
            "policy off: today's behaviour, the swap succeeds"
        );

        set_policy(&fx, ReleaseImmutability::On).await;
        assert_immutable(
            swap(
                &fx,
                router,
                tdh::put,
                &sbom("1.1.0"),
                "demo-1.1.0-cyclonedx.json",
                bytes(),
            )
            .await,
            "policy on: a release file's bytes cannot be swapped",
        );
        let snapshot = "com/example/pol/demo/1.2.0-SNAPSHOT/demo-1.2.0-SNAPSHOT.jar";
        let on_snapshot = swap(
            &fx,
            router,
            tdh::put,
            snapshot,
            "demo-1.2.0-SNAPSHOT.jar",
            bytes(),
        )
        .await;
        assert_eq!(
            on_snapshot.0,
            StatusCode::CREATED,
            "a -SNAPSHOT/ file stays replaceable"
        );
        fx.teardown().await;
    }

    fn npm_publish(package: &str, version: &str, tarball: &[u8]) -> Bytes {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD.encode(tarball);
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "name": package,
                "dist-tags": { "latest": version },
                "versions": { version: { "name": package, "version": version } },
                "_attachments": { format!("{package}-{version}.tgz"): { "data": data } }
            }))
            .unwrap(),
        )
    }

    /// A hosted npm tarball (`{pkg}/{ver}/{pkg}-{ver}.tgz`) was read as
    /// packument metadata until #33, so its bytes could be swapped after a
    /// delete whatever the policy said. With #33 it is a released coordinate
    /// under the always-on rules and the policy adds nothing; this pins that
    /// the swap is refused with the typed code under the policy, and that a
    /// fresh version still publishes.
    #[tokio::test]
    async fn npm_handler_tarball_swap_refused_with_policy_on_db() {
        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        tdh::grant_repo_role(&fx.pool, fx.repo_id, fx.user_id, "repository-owner").await;
        set_policy(&fx, ReleaseImmutability::On).await;
        let router = crate::api::handlers::npm::router;
        let pkg = "immut-policy-pkg";
        assert_immutable(
            swap(
                &fx,
                router,
                tdh::put_json,
                pkg,
                &format!("{pkg}-1.0.0.tgz"),
                (
                    npm_publish(pkg, "1.0.0", b"tgz-one"),
                    npm_publish(pkg, "1.0.0", b"tgz-two"),
                ),
            )
            .await,
            "npm tarball swap under the policy",
        );
        let (status, body) = tdh::send(
            fx.router_with_auth(router()),
            tdh::put_json(
                format!("/{}/{pkg}", fx.repo_key),
                npm_publish(pkg, "1.0.1", b"tgz-new"),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "a new version publishes: {status} {}",
            String::from_utf8_lossy(&body)
        );
        fx.teardown().await;
    }
}
