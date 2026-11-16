use sessions_sim::{experiments::*, measurements::*, oracle::LossReading, Knobs, Params};
fn main() {
    let cadence = std::env::args()
        .nth(1)
        .map_or(4, |v| v.parse::<u64>().expect("cadence must be an integer"));
    assert!(cadence > 0, "cadence must be positive");
    println!("SAFETY AND LIVENESS TABLE");
    println!("300 seeds per row (0..299), B=8, checkpoint every {cadence} app steps, fetch_owner_statement=OFF, reading=CONCURRENT.");
    println!("Violations count runs, I/O=in-bound/out-of-bound. Expected counts oracle Limits events (including G4 outside the bound and restart loss).");
    println!("Reopened: final open honest sessions / all honest sessions. Releases: distinct (seat,pool,index,digest). Burned: slot burn operations, including absent window indices.");
    println!("Refusals W/S/N/C: window_exceeded/slot_stale/no_checkpoint/conflict (includes bound-to-other). Recovery: mean sweeps after LAST fault, excluding censored runs (3-sweep budget).");
    println!("G2G3 = same index two digests; Share = same share two digests (key-leak case), both count runs I/O. Probes re-put the ORIGINAL dealt share from the ghost app/board history.");
    println!("Q11 (formerly Q13) counts runs with a second release on an account slot absent from the rollback snapshot. This leaks only if the app can obtain and re-put the same share.");
    println!("Seeds vary seat, app step and crash point: none / after fsync / after k<w seeded witness acks / after slot acks before bound seal / during restore.");
    println!("Byz C/F/S/P counts actual conflicting slot reports / forged unsigned reports / stale fetch responses / refused partials. Byzantine rows also reboot or replace ANOTHER seat; responses from the seeded adversary arrive first.");
    println!("distinct counts per-seed outcome tuples of ALL reported metrics (before percentages/means), excluding seed, seat identities and random bytes.");
    println!("A column counts reachable erased-entry or second-release outcomes. Series checkpoint between replacements; cadence applies to normal app steps.");
    for old in [false, true] {
        println!(
            "{}",
            if old {
                "old rules"
            } else {
                "fixed rules (default)"
            }
        );
        println!("kind n/f seeds distinct I/O G2G3_I/O Share_I/O G4_I/O G1_I/O expected A Q11 reopened% releases refused_W/S/N/C voided burned mean_recovery censored Byz_C/F/S/P Midnight_tx/run Midnight_bytes/run");
        for (n, f) in [(4, 1), (7, 2)] {
            for kind in FailureKind::ALL {
                let mut totals = Totals::default();
                for seed in 0..300 {
                    let mut params = Params::new(n, f);
                    params.cp_every = cadence;
                    totals.add(&run_case(
                        params,
                        seed,
                        kind,
                        if old {
                            Knobs::old_rules()
                        } else {
                            Knobs::default()
                        },
                        LossReading::Concurrent,
                    ));
                }
                let t = totals;
                let mean = if t.recovered_runs == 0 {
                    "NA".into()
                } else {
                    format!("{:.2}", t.recovery_sum as f64 / t.recovered_runs as f64)
                };
                println!(
                "{} {n}/{f} {} {} {}/{} {}/{} {}/{} {}/{} {}/{} {} {} {} {:.2} {} {}/{}/{}/{} {} {} {} {} {}/{}/{}/{} {:.2} {:.2}",
                kind.name(),
                t.runs,
                t.outcomes.len(),
                t.bounds[0],
                t.bounds[1],
                t.violations[0][0],
                t.violations[0][1],
                t.same_share[0],
                t.same_share[1],
                t.violations[1][0],
                t.violations[1][1],
                t.violations[2][0],
                t.violations[2][1],
                t.expected,
                t.a_class,
                t.q13_class,
                100.0 * t.reopened as f64 / t.sessions as f64,
                t.releases,
                t.refusals[0],
                t.refusals[1],
                t.refusals[2],
                t.refusals[3],
                t.voided,
                t.burned,
                mean,
                t.runs - t.recovered_runs,
                t.byzantine_fired[0],
                t.byzantine_fired[1],
                t.byzantine_fired[2],
                t.byzantine_fired[3],
                t.midnight_tx as f64 / t.runs as f64,
                t.midnight_bytes as f64 / t.runs as f64
            );
            }
        }
    }
    println!("Midnight tx and Midnight bytes: safety-table columns are means per run, including initial boots.");
    println!("MIDNIGHT WRITE COMPARISON (one run per row, seed=731, 12 app steps, cadence=4, whole restart, recovery checkpoint)");
    println!("rules n/f checkpoints boot_tickets put_records restore_transactions | Midnight tx | Midnight bytes");
    for (n, f) in [(4, 1), (7, 2)] {
        for old in [false, true] {
            let m = midnight_measurement(n, f, old);
            println!(
                "{} {n}/{f} {} {} {} {} | {} | {}",
                if old { "old_per_event_ledger" } else { "fixed" },
                m.checkpoints,
                m.boot_tickets,
                m.put_records,
                m.restore_transactions,
                m.tx(),
                m.bytes
            );
        }
    }
    println!(
        "FIXED SERIES (seed=731, owner_statement=OFF, CONCURRENT, F/S/A=fence/sequential/account)"
    );
    println!("n/f t w c owner+nonholders w-1<=f rollback_F/S/A checkpoint_then_rollback_F/S/A blank_owner_F/S/A");
    for (n, f) in SERIES_PARAMS {
        let params = Params::new(n, f);
        let mut columns = vec![];
        for tail in [
            SeriesTail::Rollback,
            SeriesTail::CheckpointThenRollback,
            SeriesTail::ReplaceOwner,
        ] {
            let outcomes: Vec<_> = SeriesKind::ALL
                .into_iter()
                .map(|kind| {
                    let r = replacement_series_tail(
                        params.clone(),
                        731,
                        kind,
                        false,
                        LossReading::Concurrent,
                        tail,
                    );
                    if r.resurrected || r.second_release {
                        "REPRO"
                    } else if r.open_result.is_err() {
                        "GroupUnavailable"
                    } else {
                        "safe_open"
                    }
                })
                .collect();
            columns.push(outcomes.join("/"));
        }
        println!(
            "{n}/{f} {} {} {} {} {} {}",
            params.t,
            params.w,
            params.c(),
            1 + (n - 1 - params.w),
            params.w - 1 <= f,
            columns.join(" ")
        );
    }
    println!("All five profiles reopen the latest record in every series tail under the fixed rules. CONCURRENT: in bound, peak one loss. LITERAL remains selectable through the library.");
    println!("MEASUREMENTS: B=8, session_max_bytes=2097152 (SS-004/134/135)");
    println!("SS-134 Body encoding: u16 purpose length, purpose, u64 restart_mark, u32 entry count, entries (u16 name length/name/u32 value length/value), u32 live count, slots (u64 index/u8 state/u16 share length/share/[16 put_tag account only]/[32 digest bound only]), u32 run count, runs (u64 first/u64 last). Big-endian.");
    println!("SS-135 S_max applies to accounted BODY (free counted bound). Record=52-byte header+24-byte nonce+body+16-byte tag. Base64 line=4*ceil(record/3)+LF; RPC envelope excluded. Measurement Schnorr purpose=schnorr-slots; entries empty.");
    println!("pool state body accounted_body record base64_line accounted_record accounted_line S_max_ok actual_under_1MiB line_under_4194304");
    for n in [1000, 10000] {
        for state in PoolState::ALL {
            let m = pool_measurement(n, state, 8);
            println!(
                "{n} {} {} {} {} {} {} {} {} {} {}",
                state.name(),
                m.body,
                m.accounted_body,
                m.record,
                m.line,
                m.accounted_record,
                m.accounted_line,
                m.accounted_body <= 2_097_152,
                m.record < 1_048_576,
                m.line <= 4_194_304
            );
        }
    }
    println!("10,000 bound Schnorr slots: body=1,070,035, record=1,070,127; 107 bytes per bound slot. Free slots have the same accounted size. All measured accounted bodies fit S_max; payload lines fit SS-109 (envelope excluded).");
    println!("RESTART COST VS B (n=4,f=1; per-seat sequential and account burns; one pending request at h=1; 16 account slots)");
    println!("Split cp_boot: seats 0,2 sync at cp1, seat 0 opens, cp2 lands, seat 1 opens. Union counts sequential indices across seats 0 and 1; account union=16.");
    println!("B sequential_window_plus_pending account voided split_cp_union refused_per_1000_rate1 rate4 rate16");
    for b in [1, 2, 4, 8, 16, 32, 64, 128, 256] {
        let r = restart_measurement(b);
        println!(
            "{b} {} {} {} {} {} {} {}",
            r.sequential,
            r.account,
            r.voided,
            r.union,
            window_refusals(b, 1),
            window_refusals(b, 4),
            window_refusals(b, 16)
        );
    }
    println!("Window refusals use 16 complete intervals normalized to 1,000 attempted binds, reserving unique indices even on refusal. Smallest zero-refusal B: rate1=1, rate4=4, rate16=16.");
}
