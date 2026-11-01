//! One table scan for concurrent DPF queries.
//!
//! A DPF query reads every bin of every group of its table, so queries that
//! arrive while a scan of the same table is running wait and then share the
//! next scan: one thread scans for everyone queued (`process_table_group`
//! evaluates all their keys per bin read), hands each its results, and passes
//! the scan role to the next waiter. Each result depends only on its own
//! keys, so a shared scan answers exactly what separate scans would.

use libdpf::DpfKey;
use rayon::prelude::*;
use runtime::eval::{self, GroupTiming};
use runtime::table::MappedSubTable;
use std::collections::{HashMap, VecDeque};
use std::sync::{mpsc, Mutex};

/// Per-group results of one query (`groups[g][key]`) and the timing of the
/// scan that produced them.
pub(crate) struct ScanResult {
    pub(crate) groups: Vec<Vec<Vec<u8>>>,
    pub(crate) timing: GroupTiming,
}

#[derive(Default)]
pub(crate) struct ScanBatcher {
    /// Keyed by table address (tables live as long as the server) and by
    /// whether the query runs on the free pool, so a paid query never waits
    /// on a scan running with the free lane's threads.
    lanes: Mutex<HashMap<(usize, bool), Lane>>,
}

#[derive(Default)]
struct Lane {
    scanning: bool,
    queued: VecDeque<Job>,
}

struct Job {
    keys: Vec<Vec<DpfKey>>,
    reply: mpsc::Sender<Reply>,
}

enum Reply {
    Done(ScanResult),
    Scan,
}

impl ScanBatcher {
    /// Evaluate `keys[g]` over group `g` of `table`, sharing the scan with
    /// any concurrent queries on the same table and lane. Blocks until done.
    pub(crate) fn scan(
        &self,
        table: &MappedSubTable,
        free: bool,
        keys: Vec<Vec<DpfKey>>,
    ) -> ScanResult {
        let id = (table as *const MappedSubTable as usize, free);
        let (reply, rx) = mpsc::channel();
        let scan_now = {
            let mut lanes = self.lanes.lock().unwrap();
            let lane = lanes.entry(id).or_default();
            lane.queued.push_back(Job { keys, reply });
            !std::mem::replace(&mut lane.scanning, true)
        };
        if !scan_now {
            match rx.recv().unwrap() {
                Reply::Done(result) => return result,
                Reply::Scan => {}
            }
        }
        // This query is queued, so the batch taken here contains it.
        let jobs: Vec<Job> = {
            let mut lanes = self.lanes.lock().unwrap();
            lanes.get_mut(&id).unwrap().queued.drain(..).collect()
        };
        let results = scan_jobs(table, &jobs);
        for (job, result) in jobs.iter().zip(results) {
            let _ = job.reply.send(Reply::Done(result));
        }
        {
            let mut lanes = self.lanes.lock().unwrap();
            let lane = lanes.get_mut(&id).unwrap();
            match lane.queued.front() {
                Some(next) => {
                    let _ = next.reply.send(Reply::Scan);
                }
                None => lane.scanning = false,
            }
        }
        match rx.recv().unwrap() {
            Reply::Done(result) => result,
            Reply::Scan => unreachable!("a scanned query is never handed the scan"),
        }
    }
}

fn scan_jobs(table: &MappedSubTable, jobs: &[Job]) -> Vec<ScanResult> {
    let result_size = table.params.bin_size();
    let num_groups = jobs.iter().map(|j| j.keys.len()).max().unwrap_or(0);
    let per_group: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
        .into_par_iter()
        .map(|g| {
            let keys: Vec<&DpfKey> = jobs
                .iter()
                .filter_map(|j| j.keys.get(g))
                .flatten()
                .collect();
            eval::process_table_group(
                &keys,
                table.group_bytes(g),
                table.bins_per_table,
                result_size,
            )
        })
        .collect();

    let mut timing = GroupTiming::default();
    let mut results: Vec<ScanResult> = jobs
        .iter()
        .map(|j| ScanResult {
            groups: Vec::with_capacity(j.keys.len()),
            timing: GroupTiming::default(),
        })
        .collect();
    for (g, (accs, t)) in per_group.into_iter().enumerate() {
        timing.dpf_eval += t.dpf_eval;
        timing.fetch_xor += t.fetch_xor;
        let mut accs = accs.into_iter();
        for (job, result) in jobs.iter().zip(results.iter_mut()) {
            if let Some(keys) = job.keys.get(g) {
                result.groups.push(accs.by_ref().take(keys.len()).collect());
            }
        }
    }
    for result in &mut results {
        result.timing = GroupTiming {
            dpf_eval: timing.dpf_eval,
            fetch_xor: timing.fetch_xor,
        };
    }
    results
}
