//! Deterministic, replay-safe state semantics for the ClipTown sync protocol.
//!
//! Transport and persistence deliberately sit outside this module. Keeping the
//! transition rules pure lets HTTP, cloud relay, and local-peer delivery apply
//! the same signed/encrypted mutations without changing conflict behaviour.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncCursor {
    pub server_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MutationKind {
    Upsert { payload_digest: String },
    Tombstone,
    PinChanged { pinned: bool },
    AttachmentManifest { manifest_digest: String },
    DeviceRevoked { revoked_device_id: String },
    KeyRotated { key_version: u64 },
}

impl MutationKind {
    fn deletion_precedence(&self) -> u8 {
        u8::from(matches!(self, Self::Tombstone))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncMutation {
    pub mutation_id: String,
    pub object_id: String,
    pub logical_clock: u64,
    pub device_id: String,
    pub kind: MutationKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequencedMutation {
    pub server_sequence: u64,
    pub mutation: SyncMutation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyStatus {
    Applied,
    Superseded,
    Replayed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyResult {
    pub status: ApplyStatus,
    pub cursor: SyncCursor,
}

/// The explicit output of one pure sync-state transition.
///
/// The transport/persistence shell decides when to commit `next_state`. A
/// rejected transition has no state value to commit, which makes the
/// no-mutation-on-error guarantee visible in the type signature.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "a sync transition has no effect until its next state is committed"]
pub struct SyncTransition {
    pub next_state: SyncEngine,
    pub result: ApplyResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullPage {
    pub mutations: Vec<SequencedMutation>,
    pub cursor: SyncCursor,
    pub has_more: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncError {
    InvalidMutation(&'static str),
    IdempotencyConflict,
    InvalidSnapshot(&'static str),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncEngine {
    server_sequence: u64,
    records: BTreeMap<String, SequencedMutation>,
    log: Vec<SequencedMutation>,
    replay_index: BTreeMap<String, SequencedMutation>,
    replay_order: VecDeque<String>,
    replay_capacity: usize,
}

impl SyncEngine {
    pub fn new(replay_capacity: usize) -> Result<Self, SyncError> {
        if replay_capacity == 0 {
            return Err(SyncError::InvalidMutation(
                "replay retention capacity must be positive",
            ));
        }

        Ok(Self {
            server_sequence: 0,
            records: BTreeMap::new(),
            log: Vec::new(),
            replay_index: BTreeMap::new(),
            replay_order: VecDeque::new(),
            replay_capacity,
        })
    }

    pub fn cursor(&self) -> SyncCursor {
        SyncCursor {
            server_sequence: self.server_sequence,
        }
    }

    pub fn record(&self, object_id: &str) -> Option<&SequencedMutation> {
        self.records.get(object_id)
    }

    pub fn retained_replays(&self) -> usize {
        self.replay_index.len()
    }

    /// Computes a transition without mutating the source state.
    ///
    /// This is the authoritative functional-core API. HTTP, database, and
    /// peer-transport adapters can validate, log, or atomically persist the
    /// returned next state before making it operational.
    pub fn transitioned(&self, mutation: SyncMutation) -> Result<SyncTransition, SyncError> {
        validate_mutation(&mutation)?;

        if let Some(previous) = self.replay_index.get(&mutation.mutation_id) {
            if previous.mutation != mutation {
                return Err(SyncError::IdempotencyConflict);
            }
            return Ok(SyncTransition {
                next_state: self.clone(),
                result: ApplyResult {
                    status: ApplyStatus::Replayed,
                    cursor: SyncCursor {
                        server_sequence: previous.server_sequence,
                    },
                },
            });
        }

        let next_sequence = self
            .server_sequence
            .checked_add(1)
            .ok_or(SyncError::InvalidMutation("server sequence exhausted"))?;
        let sequenced = SequencedMutation {
            server_sequence: next_sequence,
            mutation,
        };

        let status = match self.records.get(&sequenced.mutation.object_id) {
            Some(current) if !wins_conflict(&sequenced, current) => ApplyStatus::Superseded,
            _ => ApplyStatus::Applied,
        };

        let mut next_state = self.clone();
        next_state.server_sequence = next_sequence;
        if status == ApplyStatus::Applied {
            next_state
                .records
                .insert(sequenced.mutation.object_id.clone(), sequenced.clone());
        }
        next_state.log.push(sequenced.clone());
        next_state.remember_replay(sequenced);

        Ok(SyncTransition {
            result: ApplyResult {
                status,
                cursor: next_state.cursor(),
            },
            next_state,
        })
    }

    /// Compatibility shell for callers that intentionally own mutable state.
    ///
    /// All decisions are made by [Self::transitioned]; this method performs
    /// only the final commit after a successful pure transition.
    pub fn apply(&mut self, mutation: SyncMutation) -> Result<ApplyResult, SyncError> {
        let SyncTransition { next_state, result } = self.transitioned(mutation)?;
        *self = next_state;
        Ok(result)
    }

    pub fn pull(&self, after: SyncCursor, limit: usize) -> Result<PullPage, SyncError> {
        if limit == 0 {
            return Err(SyncError::InvalidMutation("pull limit must be positive"));
        }
        if after.server_sequence > self.server_sequence {
            return Err(SyncError::InvalidMutation(
                "pull cursor is ahead of the server",
            ));
        }

        let mut pending = self
            .log
            .iter()
            .filter(|entry| entry.server_sequence > after.server_sequence);
        let mutations: Vec<_> = pending.by_ref().take(limit).cloned().collect();
        let has_more = pending.next().is_some();
        let cursor = SyncCursor {
            server_sequence: mutations
                .last()
                .map_or(self.server_sequence.max(after.server_sequence), |entry| {
                    entry.server_sequence
                }),
        };

        Ok(PullPage {
            mutations,
            cursor,
            has_more,
        })
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, SyncError> {
        serde_json::to_vec(self).map_err(|_| SyncError::InvalidSnapshot("serialization failed"))
    }

    pub fn restore(snapshot: &[u8]) -> Result<Self, SyncError> {
        let engine: Self = serde_json::from_slice(snapshot)
            .map_err(|_| SyncError::InvalidSnapshot("snapshot is not valid JSON"))?;
        engine.validate_snapshot()?;
        Ok(engine)
    }

    fn remember_replay(&mut self, mutation: SequencedMutation) {
        let mutation_id = mutation.mutation.mutation_id.clone();
        self.replay_index.insert(mutation_id.clone(), mutation);
        self.replay_order.push_back(mutation_id);

        while self.replay_order.len() > self.replay_capacity {
            if let Some(expired) = self.replay_order.pop_front() {
                self.replay_index.remove(&expired);
            }
        }
    }

    fn validate_snapshot(&self) -> Result<(), SyncError> {
        if self.replay_capacity == 0 {
            return Err(SyncError::InvalidSnapshot(
                "replay retention capacity must be positive",
            ));
        }
        if self.log.len() > self.server_sequence as usize {
            return Err(SyncError::InvalidSnapshot(
                "log is longer than the server sequence",
            ));
        }

        let mut previous = 0;
        for entry in &self.log {
            if entry.server_sequence <= previous || entry.server_sequence > self.server_sequence {
                return Err(SyncError::InvalidSnapshot(
                    "log sequences are not strictly monotonic",
                ));
            }
            validate_mutation(&entry.mutation)
                .map_err(|_| SyncError::InvalidSnapshot("log contains an invalid mutation"))?;
            previous = entry.server_sequence;
        }

        if self.replay_index.len() != self.replay_order.len()
            || self.replay_index.len() > self.replay_capacity
            || self
                .replay_order
                .iter()
                .any(|mutation_id| !self.replay_index.contains_key(mutation_id))
        {
            return Err(SyncError::InvalidSnapshot(
                "replay retention index is inconsistent",
            ));
        }

        if self.records.values().any(|record| {
            record.server_sequence > self.server_sequence
                || validate_mutation(&record.mutation).is_err()
        }) {
            return Err(SyncError::InvalidSnapshot(
                "record head is outside the validated log",
            ));
        }

        Ok(())
    }
}

fn validate_mutation(mutation: &SyncMutation) -> Result<(), SyncError> {
    if mutation.mutation_id.is_empty() || mutation.mutation_id.len() > 128 {
        return Err(SyncError::InvalidMutation("invalid mutation identifier"));
    }
    if mutation.object_id.is_empty() || mutation.object_id.len() > 256 {
        return Err(SyncError::InvalidMutation("invalid object identifier"));
    }
    if mutation.device_id.is_empty() || mutation.device_id.len() > 128 {
        return Err(SyncError::InvalidMutation("invalid device identifier"));
    }
    match &mutation.kind {
        MutationKind::Upsert { payload_digest }
        | MutationKind::AttachmentManifest {
            manifest_digest: payload_digest,
        } if payload_digest.len() != 64
            || !payload_digest.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Err(SyncError::InvalidMutation(
                "payload digest must be 64 hexadecimal characters",
            ))
        }
        MutationKind::DeviceRevoked { revoked_device_id } if revoked_device_id.is_empty() => Err(
            SyncError::InvalidMutation("revoked device identifier is empty"),
        ),
        MutationKind::KeyRotated { key_version: 0 } => Err(SyncError::InvalidMutation(
            "key rotation version must be positive",
        )),
        _ => Ok(()),
    }
}

fn wins_conflict(candidate: &SequencedMutation, current: &SequencedMutation) -> bool {
    (
        candidate.mutation.logical_clock,
        candidate.mutation.kind.deletion_precedence(),
        candidate.mutation.device_id.as_str(),
        candidate.mutation.mutation_id.as_str(),
        candidate.server_sequence,
    ) > (
        current.mutation.logical_clock,
        current.mutation.kind.deletion_precedence(),
        current.mutation.device_id.as_str(),
        current.mutation.mutation_id.as_str(),
        current.server_sequence,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mutation(
        mutation_id: &str,
        object_id: &str,
        logical_clock: u64,
        device_id: &str,
        kind: MutationKind,
    ) -> SyncMutation {
        SyncMutation {
            mutation_id: mutation_id.into(),
            object_id: object_id.into(),
            logical_clock,
            device_id: device_id.into(),
            kind,
        }
    }

    fn upsert(id: &str, clock: u64, device: &str) -> SyncMutation {
        mutation(
            id,
            "clip-1",
            clock,
            device,
            MutationKind::Upsert {
                payload_digest: "a".repeat(64),
            },
        )
    }

    #[test]
    fn replay_is_idempotent_and_payload_reuse_fails_closed() {
        let mut engine = SyncEngine::new(8).unwrap();
        let original = upsert("mutation-1", 1, "device-a");
        assert_eq!(
            engine.apply(original.clone()).unwrap().status,
            ApplyStatus::Applied
        );
        assert_eq!(
            engine.apply(original).unwrap().status,
            ApplyStatus::Replayed
        );
        assert_eq!(engine.cursor().server_sequence, 1);

        let mut conflicting = upsert("mutation-1", 2, "device-a");
        conflicting.kind = MutationKind::Tombstone;
        assert_eq!(
            engine.apply(conflicting),
            Err(SyncError::IdempotencyConflict)
        );
        assert_eq!(engine.cursor().server_sequence, 1);
    }

    #[test]
    fn pure_transition_returns_next_state_without_mutating_source() {
        let source = SyncEngine::new(8).unwrap();
        let transition = source
            .transitioned(upsert("mutation-1", 1, "device-a"))
            .unwrap();

        assert_eq!(source.cursor().server_sequence, 0);
        assert!(source.record("clip-1").is_none());
        assert_eq!(transition.result.status, ApplyStatus::Applied);
        assert_eq!(transition.next_state.cursor().server_sequence, 1);
        assert!(transition.next_state.record("clip-1").is_some());
    }

    #[test]
    fn failed_mutable_shell_commit_preserves_the_complete_prior_state() {
        let mut engine = SyncEngine::new(8).unwrap();
        engine.apply(upsert("mutation-1", 1, "device-a")).unwrap();
        let before = engine.clone();

        let mut conflicting = upsert("mutation-1", 2, "device-a");
        conflicting.kind = MutationKind::Tombstone;

        assert_eq!(
            engine.apply(conflicting),
            Err(SyncError::IdempotencyConflict)
        );
        assert_eq!(engine, before);
    }

    #[test]
    fn immutable_transitions_compose_with_try_fold() {
        let mut mutations =
            (1..=3).map(|index| upsert(&format!("mutation-{index}"), index, "device-a"));

        let final_state = mutations
            .try_fold(SyncEngine::new(8).unwrap(), |state, mutation| {
                state
                    .transitioned(mutation)
                    .map(|transition| transition.next_state)
            })
            .unwrap();

        assert_eq!(final_state.cursor().server_sequence, 3);
        assert_eq!(
            final_state.record("clip-1").unwrap().mutation.logical_clock,
            3
        );
    }

    #[test]
    fn final_page_advances_cursor_independently_of_has_more() {
        let mut engine = SyncEngine::new(8).unwrap();
        for index in 1..=3 {
            engine
                .apply(upsert(&format!("mutation-{index}"), index, "device-a"))
                .unwrap();
        }

        let first = engine.pull(SyncCursor::default(), 2).unwrap();
        assert_eq!(first.cursor.server_sequence, 2);
        assert!(first.has_more);

        let final_page = engine.pull(first.cursor, 2).unwrap();
        assert_eq!(final_page.mutations.len(), 1);
        assert_eq!(final_page.cursor.server_sequence, 3);
        assert!(!final_page.has_more);

        let empty = engine.pull(final_page.cursor, 2).unwrap();
        assert!(empty.mutations.is_empty());
        assert_eq!(empty.cursor, final_page.cursor);
        assert!(!empty.has_more);
    }

    #[test]
    fn conflict_winner_is_independent_of_delivery_order() {
        let left = upsert("mutation-left", 7, "device-a");
        let right = upsert("mutation-right", 7, "device-z");
        let mut forward = SyncEngine::new(8).unwrap();
        let mut reverse = SyncEngine::new(8).unwrap();

        forward.apply(left.clone()).unwrap();
        forward.apply(right.clone()).unwrap();
        reverse.apply(right.clone()).unwrap();
        reverse.apply(left).unwrap();

        assert_eq!(
            forward.record("clip-1").unwrap().mutation,
            reverse.record("clip-1").unwrap().mutation
        );
        assert_eq!(forward.record("clip-1").unwrap().mutation, right);
    }

    #[test]
    fn tombstone_wins_equal_clock_and_cannot_be_resurrected_by_older_data() {
        let mut engine = SyncEngine::new(8).unwrap();
        engine
            .apply(upsert("mutation-live", 9, "device-z"))
            .unwrap();
        engine
            .apply(mutation(
                "mutation-delete",
                "clip-1",
                9,
                "device-a",
                MutationKind::Tombstone,
            ))
            .unwrap();
        assert!(matches!(
            engine.record("clip-1").unwrap().mutation.kind,
            MutationKind::Tombstone
        ));

        assert_eq!(
            engine
                .apply(upsert("mutation-stale", 8, "device-z"))
                .unwrap()
                .status,
            ApplyStatus::Superseded
        );
        assert!(matches!(
            engine.record("clip-1").unwrap().mutation.kind,
            MutationKind::Tombstone
        ));
    }

    #[test]
    fn restart_preserves_cursor_heads_and_duplicate_suppression() {
        let mut engine = SyncEngine::new(8).unwrap();
        let original = upsert("mutation-1", 1, "device-a");
        engine.apply(original.clone()).unwrap();
        let snapshot = engine.snapshot().unwrap();

        let mut restarted = SyncEngine::restore(&snapshot).unwrap();
        assert_eq!(restarted.cursor(), engine.cursor());
        assert_eq!(restarted.record("clip-1"), engine.record("clip-1"));
        assert_eq!(
            restarted.apply(original).unwrap().status,
            ApplyStatus::Replayed
        );
        assert_eq!(restarted.cursor().server_sequence, 1);
    }

    #[test]
    fn replay_retention_is_bounded_without_losing_the_mutation_log() {
        let mut engine = SyncEngine::new(2).unwrap();
        for index in 1..=3 {
            engine
                .apply(upsert(&format!("mutation-{index}"), index, "device-a"))
                .unwrap();
        }

        assert_eq!(engine.retained_replays(), 2);
        let page = engine.pull(SyncCursor::default(), 10).unwrap();
        assert_eq!(page.mutations.len(), 3);
        assert_eq!(page.cursor.server_sequence, 3);
    }
}
