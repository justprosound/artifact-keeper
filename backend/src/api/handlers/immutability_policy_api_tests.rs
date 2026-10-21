//! #4812: the release immutability policy through the repository API. Create,
//! get, update and list round-trip `release_immutability` and
//! `immutability_exclusions`; refused combinations leave nothing behind; a
//! weakening update is audited; virtual deploys use the member's policy.

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use axum::extract::{Extension, Path, Query, State};

    use crate::api::extractors::Json;
    use bytes::Bytes;
    use uuid::Uuid;

    use crate::api::handlers::repositories::{
        create_repository, get_repository, list_repositories, update_repository,
        ListRepositoriesQuery, RepositoryResponse, UpdateRepositoryRequest,
    };
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::middleware::auth::AuthExtension;
    use crate::api::SharedState;
    use crate::error::{AppError, Result};
    use crate::services::release_immutability::{self, ReleaseImmutability};

    struct Rig {
        pool: sqlx::PgPool,
        state: SharedState,
        user_id: Uuid,
        username: String,
        dir: std::path::PathBuf,
        repo_ids: Vec<Uuid>,
    }

    impl Rig {
        async fn new() -> Option<Self> {
            let pool = tdh::try_pool().await?;
            let (user_id, username) = tdh::create_user(&pool).await;
            let dir = std::env::temp_dir().join(format!("immut-api-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("create storage dir");
            let state = tdh::build_state(pool.clone(), dir.to_str().unwrap());
            Some(Self {
                pool,
                state,
                user_id,
                username,
                dir,
                repo_ids: Vec::new(),
            })
        }

        fn admin(&self) -> Extension<Option<AuthExtension>> {
            let mut auth = tdh::make_auth(self.user_id, &self.username);
            auth.is_admin = true;
            Extension(Some(auth))
        }

        fn key(prefix: &str) -> String {
            format!("{prefix}-{}", Uuid::new_v4().simple())
        }

        async fn create(&mut self, body: serde_json::Value) -> Result<RepositoryResponse> {
            let Json(created) = create_repository(
                State(self.state.clone()),
                self.admin(),
                Bytes::from(serde_json::to_vec(&body).unwrap()),
            )
            .await?;
            self.repo_ids.push(created.id);
            Ok(created)
        }

        async fn update_as(
            &self,
            auth: Extension<Option<AuthExtension>>,
            key: &str,
            body: serde_json::Value,
        ) -> Result<RepositoryResponse> {
            let payload: UpdateRepositoryRequest = serde_json::from_value(body).unwrap();
            update_repository(
                State(self.state.clone()),
                auth,
                Path(key.to_string()),
                Json(payload),
            )
            .await
            .map(|Json(r)| r)
        }

        async fn update(&self, key: &str, body: serde_json::Value) -> Result<RepositoryResponse> {
            self.update_as(self.admin(), key, body).await
        }

        async fn get(&self, key: &str) -> RepositoryResponse {
            let Json(r) = get_repository(State(self.state.clone()), self.admin(), Path(key.into()))
                .await
                .expect("GET must succeed");
            r
        }

        async fn listed(&self, key: &str) -> RepositoryResponse {
            let query: ListRepositoriesQuery =
                serde_json::from_value(serde_json::json!({ "q": key, "per_page": 100 })).unwrap();
            let Json(list) =
                list_repositories(State(self.state.clone()), self.admin(), Query(query))
                    .await
                    .expect("list must succeed");
            list.items
                .into_iter()
                .find(|r| r.key == key)
                .expect("the repository must be listed")
        }

        async fn row_count(&self, key: &str) -> i64 {
            sqlx::query_scalar("SELECT COUNT(*) FROM repositories WHERE key = $1")
                .bind(key)
                .fetch_one(&self.pool)
                .await
                .unwrap()
        }

        async fn done(self) {
            for id in &self.repo_ids {
                tdh::cleanup(&self.pool, *id, self.user_id).await;
            }
            tdh::cleanup_user(&self.pool, self.user_id).await;
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn local(key: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut body = serde_json::json!({
            "key": key, "name": key, "format": "generic", "repo_type": "local"
        });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    }

    fn assert_policy(r: &RepositoryResponse, mode: ReleaseImmutability, exclusions: &[&str]) {
        assert_eq!(r.release_immutability, mode, "{}", r.key);
        assert_eq!(r.immutability_exclusions, exclusions, "{}", r.key);
    }

    fn assert_validation(result: Result<RepositoryResponse>, needle: &str) {
        match result {
            Err(AppError::Validation(m)) => assert!(m.contains(needle), "{m}"),
            other => panic!(
                "expected a 400 naming {needle}, got {:?}",
                other.map(|r| r.key)
            ),
        }
    }

    #[tokio::test]
    async fn policy_round_trips_through_create_get_update_and_list_db() {
        let Some(mut rig) = Rig::new().await else {
            return;
        };
        let plain = Rig::key("immut-default");
        let created = rig
            .create(local(&plain, serde_json::json!({})))
            .await
            .unwrap();
        assert_policy(&created, ReleaseImmutability::Off, &[]);
        assert_policy(&rig.listed(&plain).await, ReleaseImmutability::Off, &[]);

        let key = Rig::key("immut-on");
        let created = rig
            .create(local(
                &key,
                serde_json::json!({
                    "release_immutability": "on",
                    "immutability_exclusions": [" nightly ", "latest", "nightly"]
                }),
            ))
            .await
            .unwrap();
        assert_policy(&created, ReleaseImmutability::On, &["latest", "nightly"]);
        assert_policy(
            &rig.get(&key).await,
            ReleaseImmutability::On,
            &["latest", "nightly"],
        );
        assert_policy(
            &rig.listed(&key).await,
            ReleaseImmutability::On,
            &["latest", "nightly"],
        );

        let r = rig
            .update(&key, serde_json::json!({ "description": "unrelated" }))
            .await
            .unwrap();
        assert_policy(&r, ReleaseImmutability::On, &["latest", "nightly"]);

        let r = rig
            .update(&key, serde_json::json!({ "immutability_exclusions": [] }))
            .await
            .unwrap();
        assert_policy(&r, ReleaseImmutability::On, &[]);

        assert_validation(
            rig.update(
                &key,
                serde_json::json!({ "immutability_exclusions": ["a/b"] }),
            )
            .await,
            "immutability_exclusions",
        );
        assert_policy(&rig.get(&key).await, ReleaseImmutability::On, &[]);

        let r = rig
            .update(&key, serde_json::json!({ "release_immutability": "off" }))
            .await
            .unwrap();
        assert_policy(&r, ReleaseImmutability::Off, &[]);
        rig.done().await;
    }

    #[tokio::test]
    async fn refused_policies_leave_no_repository_behind_db() {
        let Some(mut rig) = Rig::new().await else {
            return;
        };
        let remote = Rig::key("immut-remote");
        assert_validation(
            rig.create(serde_json::json!({
                "key": remote, "name": remote, "format": "generic", "repo_type": "remote",
                "upstream_url": "https://upstream.example.test",
                "release_immutability": "on"
            }))
            .await,
            "hosted member",
        );
        assert_eq!(rig.row_count(&remote).await, 0);

        // The untouched-form defaults are accepted on a virtual repository.
        let virt = Rig::key("immut-virtual");
        let created = rig
            .create(serde_json::json!({
                "key": virt, "name": virt, "format": "generic", "repo_type": "virtual",
                "release_immutability": "off", "immutability_exclusions": []
            }))
            .await
            .unwrap();
        assert_policy(&created, ReleaseImmutability::Off, &[]);

        let versioned = Rig::key("immut-versioned");
        assert_validation(
            rig.create(local(
                &versioned,
                serde_json::json!({ "versioning_enabled": true, "release_immutability": "on" }),
            ))
            .await,
            "versioning_enabled",
        );
        assert_eq!(rig.row_count(&versioned).await, 0);

        let key = Rig::key("immut-then-versioning");
        rig.create(local(
            &key,
            serde_json::json!({ "release_immutability": "on" }),
        ))
        .await
        .unwrap();
        assert_validation(
            rig.update(&key, serde_json::json!({ "versioning_enabled": true }))
                .await,
            "versioning_enabled",
        );
        assert!(!rig.get(&key).await.versioning_enabled);
        rig.done().await;
    }

    #[tokio::test]
    async fn loosening_needs_repository_admin_and_is_audited_db() {
        let Some(mut rig) = Rig::new().await else {
            return;
        };
        let key = Rig::key("immut-audit");
        let created = rig
            .create(local(
                &key,
                serde_json::json!({ "release_immutability": "on" }),
            ))
            .await
            .unwrap();

        // A writer without the repository `admin` action cannot weaken it.
        let (writer_id, writer_name) = tdh::create_user(&rig.pool).await;
        tdh::grant_repo_actions(&rig.pool, created.id, writer_id, &["read", "write"]).await;
        let err = rig
            .update_as(
                Extension(Some(tdh::make_auth(writer_id, &writer_name))),
                &key,
                serde_json::json!({ "release_immutability": "off" }),
            )
            .await;
        assert!(
            matches!(err, Err(AppError::Authorization(_))),
            "{:?}",
            err.map(|r| r.key)
        );
        assert!(release_immutability::load(&rig.pool, created.id)
            .await
            .unwrap()
            .is_on());

        rig.update(
            &key,
            serde_json::json!({ "release_immutability": "off", "immutability_exclusions": ["nightly"] }),
        )
        .await
        .unwrap();
        let row = tdh::audit_row_eventually(&rig.pool, created.id, "REPOSITORY_UPDATED").await;
        assert_eq!(
            row.details["release_immutability_change"],
            serde_json::json!({
                "previous_release_immutability": "on",
                "release_immutability": "off",
                "previous_immutability_exclusions": [],
                "immutability_exclusions": ["nightly"],
                "loosened": true
            })
        );
        let row = tdh::audit_row_eventually(&rig.pool, created.id, "REPOSITORY_CREATED").await;
        assert_eq!(
            row.details["release_immutability_change"]["release_immutability"],
            "on"
        );
        assert_eq!(
            row.details["release_immutability_change"]["loosened"],
            false
        );

        tdh::cleanup_user(&rig.pool, writer_id).await;
        rig.done().await;
    }

    /// A publish addressed at a virtual repository lands in its hosted
    /// member, and the member's policy is the one that protects it.
    #[tokio::test]
    async fn virtual_deploy_target_carries_the_member_policy_db() {
        let Some(mut rig) = Rig::new().await else {
            return;
        };
        let member = Rig::key("immut-member");
        let member_repo = rig
            .create(local(
                &member,
                serde_json::json!({ "release_immutability": "on" }),
            ))
            .await
            .unwrap();
        let virt = Rig::key("immut-front");
        let front = rig
            .create(serde_json::json!({
                "key": virt, "name": virt, "format": "generic", "repo_type": "virtual",
                "member_repos": [{ "repo_key": member }]
            }))
            .await
            .unwrap();

        let mut auth = tdh::make_auth(rig.user_id, &rig.username);
        auth.is_admin = true;
        let target = crate::api::handlers::proxy_helpers::resolve_virtual_deploy_target(
            &rig.pool,
            &rig.state.permission_service,
            &auth,
            front.id,
        )
        .await
        .expect("the hosted member is the deploy target");
        assert_eq!(target.id, member_repo.id);
        assert!(
            release_immutability::is_protected(&rig.pool, &target, "app/1.0/app.tgz")
                .await
                .unwrap()
        );

        sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(front.id)
            .execute(&rig.pool)
            .await
            .unwrap();
        rig.done().await;
    }
}
