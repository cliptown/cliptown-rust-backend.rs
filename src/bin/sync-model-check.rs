#![forbid(unsafe_code)]

#[path = "../sync_protocol.rs"]
mod sync_protocol;

use std::collections::{BTreeMap, VecDeque};

use sync_protocol::{
    ApplyStatus, MutationKind, SequencedMutation, SyncCursor, SyncEngine, SyncError, SyncMutation,
};

const REPLAY_CAPACITY: usize = 2;
const MAX_DEPTH: usize = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Model {
    server_sequence: u64,
    winner: Option<SequencedMutation>,
    log: Vec<SequencedMutation>,
    replay_index: BTreeMap<String, SequencedMutation>,
    replay_order: VecDeque<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelResult {
    Accepted {
        status: ApplyStatus,
        result_cursor: u64,
    },
    IdempotencyConflict,
}

impl Model {
    fn new() -> Self {
        Self {
            server_sequence: 0,
            winner: None,
            log: Vec::new(),
            replay_index: BTreeMap::new(),
            replay_order: VecDeque::new(),
        }
    }

    fn apply(&mut self, mutation: SyncMutation) -> ModelResult {
        if let Some(previous) = self.replay_index.get(&mutation.mutation_id) {
            return if previous.mutation == mutation {
                ModelResult::Accepted {
                    status: ApplyStatus::Replayed,
                    result_cursor: previous.server_sequence,
                }
            } else {
                ModelResult::IdempotencyConflict
            };
        }

        self.server_sequence += 1;
        let sequenced = SequencedMutation {
            server_sequence: self.server_sequence,
            mutation,
        };
        let status = match &self.winner {
            Some(current) if !wins(&sequenced, current) => ApplyStatus::Superseded,
            _ => ApplyStatus::Applied,
        };
        if status == ApplyStatus::Applied {
            self.winner = Some(sequenced.clone());
        }
        self.log.push(sequenced.clone());

        let mutation_id = sequenced.mutation.mutation_id.clone();
        self.replay_index.insert(mutation_id.clone(), sequenced);
        self.replay_order.push_back(mutation_id);
        while self.replay_order.len() > REPLAY_CAPACITY {
            let expired = self
                .replay_order
                .pop_front()
                .expect("an over-capacity replay queue is nonempty");
            self.replay_index.remove(&expired);
        }

        ModelResult::Accepted {
            status,
            result_cursor: self.server_sequence,
        }
    }
}

fn deletion_precedence(kind: &MutationKind) -> u8 {
    u8::from(matches!(kind, MutationKind::Tombstone))
}

fn wins(candidate: &SequencedMutation, current: &SequencedMutation) -> bool {
    (
        candidate.mutation.logical_clock,
        deletion_precedence(&candidate.mutation.kind),
        candidate.mutation.device_id.as_str(),
        candidate.mutation.mutation_id.as_str(),
        candidate.server_sequence,
    ) > (
        current.mutation.logical_clock,
        deletion_precedence(&current.mutation.kind),
        current.mutation.device_id.as_str(),
        current.mutation.mutation_id.as_str(),
        current.server_sequence,
    )
}

fn mutation(
    mutation_id: &str,
    logical_clock: u64,
    device_id: &str,
    kind: MutationKind,
) -> SyncMutation {
    SyncMutation {
        mutation_id: mutation_id.to_owned(),
        object_id: "clip-1".to_owned(),
        logical_clock,
        device_id: device_id.to_owned(),
        kind,
    }
}

fn cases() -> Vec<SyncMutation> {
    vec![
        mutation(
            "mutation-a",
            1,
            "device-a",
            MutationKind::Upsert {
                payload_digest: "a".repeat(64),
            },
        ),
        mutation(
            "mutation-b",
            1,
            "device-z",
            MutationKind::Upsert {
                payload_digest: "b".repeat(64),
            },
        ),
        mutation("mutation-c", 1, "device-a", MutationKind::Tombstone),
        mutation("mutation-a", 2, "device-a", MutationKind::Tombstone),
    ]
}

fn assert_observational_equivalence(engine: &SyncEngine, model: &Model) {
    assert_eq!(engine.cursor().server_sequence, model.server_sequence);
    assert_eq!(engine.retained_replays(), model.replay_index.len());
    assert_eq!(engine.record("clip-1"), model.winner.as_ref());

    let page = engine
        .pull(SyncCursor::default(), 64)
        .expect("the model always requests a positive, in-range page");
    assert_eq!(page.mutations, model.log);
    assert_eq!(page.cursor.server_sequence, model.server_sequence);
    assert!(!page.has_more);

    let snapshot = engine.snapshot().expect("serialize validated state");
    let restored = SyncEngine::restore(&snapshot).expect("restore production snapshot");
    assert_eq!(restored.cursor(), engine.cursor());
    assert_eq!(restored.record("clip-1"), engine.record("clip-1"));
    assert_eq!(restored.retained_replays(), engine.retained_replays());
    assert_eq!(
        restored
            .pull(SyncCursor::default(), 64)
            .expect("pull restored state"),
        page
    );
}

fn verify_sequence(sequence: &[usize], cases: &[SyncMutation]) -> usize {
    let mut engine = SyncEngine::new(REPLAY_CAPACITY).expect("positive replay capacity");
    let mut model = Model::new();
    let mut transitions = 0;

    assert_observational_equivalence(&engine, &model);
    for case in sequence {
        transitions += 1;
        let mutation = cases[*case].clone();
        let before_engine = engine.clone();
        let before_model = model.clone();
        let expected = model.apply(mutation.clone());
        let actual = engine.apply(mutation);

        match expected {
            ModelResult::Accepted {
                status,
                result_cursor,
            } => {
                let result = actual.expect("the abstract model accepted this mutation");
                assert_eq!(result.status, status);
                assert_eq!(result.cursor.server_sequence, result_cursor);
            }
            ModelResult::IdempotencyConflict => {
                assert_eq!(actual, Err(SyncError::IdempotencyConflict));
                assert_eq!(engine, before_engine);
                model = before_model;
            }
        }
        assert_observational_equivalence(&engine, &model);
    }

    transitions
}

fn explore(
    prefix: &mut Vec<usize>,
    cases: &[SyncMutation],
    sequences: &mut usize,
    transitions: &mut usize,
) {
    *sequences += 1;
    *transitions += verify_sequence(prefix, cases);
    if prefix.len() == MAX_DEPTH {
        return;
    }

    for index in 0..cases.len() {
        prefix.push(index);
        explore(prefix, cases, sequences, transitions);
        prefix.pop();
    }
}

fn main() {
    let cases = cases();
    let mut sequences = 0;
    let mut transitions = 0;
    explore(&mut Vec::new(), &cases, &mut sequences, &mut transitions);
    println!(
        "sync refinement: {sequences} sequences, {transitions} transitions, depth {MAX_DEPTH}; all invariants hold"
    );
}
