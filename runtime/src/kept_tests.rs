//! Files on the ship, part 3: what the owner opened from another ship is kept for a while, and
//! a copy can be saved for good. Real runtimes on this machine, as in part 2 (the helpers and
//! the liar are the parent module's); failures at chosen points through the seams of
//! `files::seams`, which work on the thread that arms them, so those tests call the runtime
//! directly rather than through the HTTP server's threads. Each test says which letters of the
//! contract (H1 to H10) it shows.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::params;
use ship_proto::{peer_reply, peer_request, FileBytes, FileFacts, FileHashes, FileWanted, Message, PeerReply, PeerRequest, Pong, SaveRequest};

use super::{contents, crewed, fast, hex, http, kept_from_acting, put, request, say, held_net, two, two_uncached, two_with, Answer, TempDir, Two, WAITING};
use crate::files::{self, seams, FileError, Holder, Part, Served, CHUNK};
use crate::kept::{Cleared, THROW_FILES};
use crate::net::{Lie, NetConfig};
use crate::server::{Server, ServerConfig};
use crate::{lock, seal, store, Config, Error, Runtime};

/// ~nec's files directory.
fn b_files(t: &Two) -> PathBuf {
    t._dirs.1 .0.join("files/nec")
}

/// Each directory under `root`, and the names in it.
fn on_disk(root: &Path) -> BTreeMap<String, BTreeSet<String>> {
    let Ok(entries) = fs::read_dir(root) else { return BTreeMap::new() };
    entries
        .map(|entry| entry.unwrap())
        .map(|entry| {
            let names = fs::read_dir(entry.path()).map(|inner| inner.map(|e| e.unwrap().file_name().into_string().unwrap()).collect()).unwrap_or_default();
            (entry.file_name().into_string().unwrap(), names)
        })
        .collect()
}

/// The kept file `id` on `ship`, and each of its pieces' copy if held.
fn kept_of(rt: &Runtime, ship: &str, id: &[u8; 32]) -> Option<(store::KeptFile, Vec<Option<store::Gen>>)> {
    rt.inner
        .with_ship(ship, |held| {
            let conn = lock(&held.conn);
            let Some(kept) = store::kept_get(&conn, id)? else { return Ok(None) };
            let pieces = (0..files::chunk_count(kept.length)).map(|n| Ok(store::kept_piece(&conn, &kept.dir, n)?.expect("a row for every chunk").1)).collect::<Result<Vec<_>, Error>>()?;
            Ok(Some((kept, pieces)))
        })
        .unwrap()
}

/// Wait until the kept file `id` on `ship` holds piece `n`, or every piece for `None`. A piece
/// fetched for an answer is kept after the device has the answer, so a test waits on that, and
/// never on a fixed pause.
fn held_soon(rt: &Runtime, ship: &str, id: &[u8; 32], n: Option<usize>) {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some((_, pieces)) = kept_of(rt, ship, id) {
            let held = match n {
                Some(n) => pieces.get(n).is_some_and(Option::is_some),
                None => pieces.iter().all(Option::is_some),
            };
            if held {
                return;
            }
        }
        assert!(Instant::now() < until, "piece {n:?} of {} was never kept", hex(id));
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The strays this runtime counts in a kept directory (0 with no record).
fn strays(rt: &Runtime, ship: &str, dir: &[u8; 16]) -> u32 {
    rt.inner.dir_record(ship.trim_start_matches('~'), dir).map_or(0, |record| record.strays)
}

fn kept_count(rt: &Runtime, ship: &str) -> usize {
    rt.inner.with_ship(ship, |held| Ok(store::kept_count(&lock(&held.conn))?)).unwrap()
}

/// Run a statement on a ship's file, as a test only can.
fn sql(rt: &Runtime, ship: &str, statement: &str, values: impl rusqlite::Params) {
    rt.inner.with_ship(ship, |held| held.transact(|conn| Ok(conn.execute(statement, values).map(drop)?))).unwrap();
}

/// What must hold of a ship at every rest (H1, H5): every row that names a copy, a kept file's
/// or a file's, names one that is there and reads back whole and matching its hash; a kept
/// file's held bytes are those of its pieces held; the cache is within its allowance; and held
/// and reserved file bytes are within the file allowance.
fn consistent(rt: &Runtime, ship: &str) {
    let cfg = &rt.inner.cfg;
    let (named, cache, counted) = rt
        .inner
        .with_ship(ship, |held| {
            let conn = lock(&held.conn);
            let mut named = Vec::new();
            for (_, kept) in store::kept_list(&conn, &[], 1_000_000)? {
                let mut bytes = 0;
                for n in 0..files::chunk_count(kept.length) {
                    let (hash, gen) = store::kept_piece(&conn, &kept.dir, n)?.expect("a row for every chunk");
                    let len = files::chunk_len(kept.length, n).unwrap();
                    if let Some(gen) = gen {
                        named.push((kept.dir, n, gen, len, hash));
                        bytes += len;
                    }
                }
                assert_eq!(kept.held, bytes, "a kept file's held bytes are not those of its pieces");
            }
            for (_, dir, length) in store::all_files(&conn)? {
                let rows = store::chunks(&conn, &dir, 0, files::chunk_count(length))?.expect("every chunk of a file");
                for (n, (hash, gen)) in rows.into_iter().enumerate() {
                    named.push((dir, n as u64, gen, files::chunk_len(length, n as u64).unwrap(), hash));
                }
            }
            Ok((named, store::cache_bytes(&conn)?, store::file_bytes(&conn)? + store::reserved_bytes(&conn)?))
        })
        .unwrap();
    let ship = ship.trim_start_matches('~');
    for (dir, n, gen, len, hash) in named {
        assert!(matches!(rt.inner.read_copy(ship, &dir, n, &gen, len, &hash), files::ReadBack::Good(_)), "a row names copy {n}.{} that is not right", hex(&gen));
    }
    assert!(cache <= cfg.max_cache_bytes, "the cache holds {cache}, over {}", cfg.max_cache_bytes);
    assert!(counted <= cfg.max_file_bytes, "held and reserved {counted}, over {}", cfg.max_file_bytes);
}

/// Count every question ~zod's network is asked about a file, changing nothing.
fn counting(t: &Two) -> Arc<AtomicUsize> {
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    t.lie(move |_, _| {
        count.fetch_add(1, Ordering::SeqCst);
        None
    });
    asked
}

/// The index a request for a part of a file names, if it is a request for a chunk.
fn chunk_asked(body: &peer_request::Body) -> Option<u64> {
    match body {
        peer_request::Body::FileChunk(wanted) => Some(wanted.index),
        _ => None,
    }
}

/// Save, for `agent` on ~nec, the file `id` that `counter` on ~zod claims: one call.
fn save(t: &Two, agent: &str, id: &[u8; 32]) -> Answer {
    let body = SaveRequest { ship: "~zod".into(), agent: "counter".into(), id: id.to_vec() }.encode_to_vec();
    request(&t.server, "POST", &format!("/ships/nec/agents/{agent}/files/save"), &[("Authorization", &t.auth)], &body)
}

fn save_reply(answer: &Answer) -> (bool, u64, u64) {
    assert_eq!(answer.status, 200, "{}", answer.text());
    let reply = ship_proto::SaveReply::decode(&*answer.body).unwrap();
    (reply.done, reply.held, reply.chunks)
}

fn device(t: &Two, method: &str, path: &str) -> Answer {
    request(&t.server, method, path, &[("Authorization", &t.auth)], b"")
}

/// A file put on ~zod under `counter` and marked open to every ship.
fn open_file(t: &Two, data: &[u8], media_type: &str) -> [u8; 32] {
    let id = put(&t.a, "~zod", "counter", data, media_type);
    assert_eq!(say(&t.a, "~zod", "counter", &format!("open {}", hex(&id))), "true");
    id
}

/// ~nec's network asking with a short deadline, so that a ship that is gone is given up on
/// quickly.
fn quick() -> NetConfig {
    NetConfig { file_timeout: Duration::from_millis(2000), request_timeout: Duration::from_millis(2000), ..NetConfig::default() }
}

/// A runtime of its own, with no network, whose ~zod keeps files put in place directly.
fn lone(dir: &TempDir, cfg: Config) -> Arc<Runtime> {
    crewed(dir, cfg, &["~zod"], "~nec")
}

/// Keep `data` on a lone runtime's ship as if it had been fetched and checked: its row, then
/// every piece. Returns its id and directory.
fn keep_lone(rt: &Runtime, ship: &str, data: &[u8]) -> ([u8; 32], [u8; 16]) {
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(files::leaf).collect();
    let id = files::id_of(data);
    let dir = rt.begin_keeping(ship, &id, data.len() as u64, "application/octet-stream", &leaves, None).unwrap();
    for (n, piece) in data.chunks(CHUNK as usize).enumerate() {
        rt.keep_piece(ship, &id, &dir, data.len() as u64, n as u64, piece.to_vec()).unwrap();
    }
    (id, dir)
}

/// What is opened is kept, and a kept file whose wanted pieces are all held opens with nothing
/// asked of the other ship, and with the other ship gone; what is not held is still fetched.
/// (H7, H1)
#[test]
fn a_file_opened_is_kept_and_opens_again_with_no_network() {
    let t = two_with("again", (fast(), NetConfig::default()), (fast(), quick()), &["~nec"]);
    let data = contents(3 * CHUNK as usize + 5, 1);
    let id = open_file(&t, &data, "image/png");
    let whole = t.get(&t.path("counter", &id, "/content"), &[]);
    assert!(whole.status == 200 && whole.body == data);
    held_soon(&t.b, "nec", &id, None);
    let (kept, pieces) = kept_of(&t.b, "nec", &id).expect("the file is kept");
    assert_eq!((kept.length, kept.held, kept.saving, kept.media_type.as_str()), (data.len() as u64, data.len() as u64, false, "image/png"));
    assert!(pieces.iter().all(Option::is_some));
    consistent(&t.b, "nec");
    // One chunk of another file.
    let other = contents(2 * CHUNK as usize, 2);
    let other_id = open_file(&t, &other, "");
    assert_eq!(t.get(&t.path("counter", &other_id, "/chunks/1"), &[]).body, other[CHUNK as usize..]);
    held_soon(&t.b, "nec", &other_id, Some(1));
    assert_eq!(kept_of(&t.b, "nec", &other_id).unwrap().1[0], None);
    // The listing.
    let listed = ship_proto::KeptList::decode(&*device(&t, "GET", "/ships/nec/files/kept").body).unwrap();
    let mut seen: Vec<(Vec<u8>, u64, u64, bool)> = listed.kept.iter().map(|kept| (kept.id.clone(), kept.length, kept.held, kept.saving)).collect();
    seen.sort();
    let mut expected = vec![(id.to_vec(), data.len() as u64, data.len() as u64, false), (other_id.to_vec(), other.len() as u64, CHUNK, false)];
    expected.sort();
    assert_eq!(seen, expected);
    // Nothing is asked of ~zod for what is held.
    let asked = counting(&t);
    assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    assert_eq!(t.get(&t.path("counter", &id, "/chunks/2"), &[]).body, data[2 * CHUNK as usize..3 * CHUNK as usize]);
    let info = ship_proto::FileInfo::decode(&*t.get(&t.path("counter", &id, ""), &[]).body).unwrap();
    assert_eq!((info.length, info.media_type.as_str()), (data.len() as u64, "image/png"));
    assert_eq!(asked.load(Ordering::SeqCst), 0, "~zod was asked about a file ~nec holds");
    // With ~zod gone, what is held is had, whole and by range; what is not, is not.
    let (content, one, nought) = (t.path("counter", &id, "/content"), t.path("counter", &other_id, "/chunks/1"), t.path("counter", &other_id, "/chunks/0"));
    drop(t.a_net);
    let auth = ("Authorization", t.auth.as_str());
    let again = http(&t.server, &content, &[auth]);
    assert!(again.status == 200 && again.body == data);
    kept_from_acting(&again);
    assert_eq!(again.header("Content-Disposition"), Some("inline"));
    let part = http(&t.server, &content, &[auth, ("Range", &format!("bytes=5-{}", CHUNK + 9))]);
    assert!(part.status == 206 && part.body == data[5..=CHUNK as usize + 9]);
    assert_eq!(http(&t.server, &one, &[auth]).status, 200);
    assert_eq!(http(&t.server, &nought, &[auth]).status, 504);
}

/// A piece held that is damaged, missing or cut short is never served: it is given up, by the
/// rule, and fetched again. One that cannot be read for another reason is not given up. With
/// the other ship gone, a damaged piece ends the answer short, never with a wrong byte.
/// (H1, rule 3)
#[test]
fn a_damaged_or_missing_piece_is_given_up_and_fetched_again() {
    let t = two_with("damaged", (fast(), NetConfig::default()), (fast(), quick()), &["~nec"]);
    let data = contents(3 * CHUNK as usize, 3);
    let id = open_file(&t, &data, "");
    assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    held_soon(&t.b, "nec", &id, None);
    let (kept, before) = kept_of(&t.b, "nec", &id).unwrap();
    let place = b_files(&t).join(hex(&kept.dir));
    let copy = |n: usize, gen: &store::Gen| place.join(format!("{n}.{}", hex(gen)));
    let mut flipped = fs::read(copy(0, &before[0].unwrap())).unwrap();
    flipped[40] ^= 1;
    fs::write(copy(0, &before[0].unwrap()), flipped).unwrap();
    fs::remove_file(copy(1, &before[1].unwrap())).unwrap();
    let short = fs::read(copy(2, &before[2].unwrap())).unwrap();
    fs::write(copy(2, &before[2].unwrap()), &short[..100]).unwrap();
    assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    held_soon(&t.b, "nec", &id, None);
    let (_, after) = kept_of(&t.b, "nec", &id).unwrap();
    for n in 0..3 {
        assert!(after[n].is_some() && after[n] != before[n], "piece {n} was not given up and kept again");
        assert!(!copy(n, &before[n].unwrap()).exists(), "the bad copy of piece {n} is still on disk");
    }
    assert_eq!(t.b.files_to_remove("nec").unwrap(), (0, 0));
    consistent(&t.b, "nec");
    // Not read, for a reason that says nothing about the copy: fetched, and the copy kept.
    let mut opened = t.b.open_remote("nec", "zod", "counter", &id).unwrap();
    seams::arm("read-copy");
    assert_eq!(opened.piece(0).unwrap(), (data[..CHUNK as usize].to_vec(), true));
    drop(opened);
    assert_eq!(kept_of(&t.b, "nec", &id).unwrap().1[0], after[0], "a copy that was only not read was given up");
    // ~zod gone, and a piece damaged: the answer ends short, and every byte in it is right.
    let mut flipped = fs::read(copy(1, &after[1].unwrap())).unwrap();
    flipped[40] ^= 1;
    fs::write(copy(1, &after[1].unwrap()), flipped).unwrap();
    let (content, one) = (t.path("counter", &id, "/content"), t.path("counter", &id, "/chunks/1"));
    let mut opened = t.b.open_remote("nec", "zod", "counter", &id).unwrap();
    drop(t.a_net);
    // Given up in a synced commit, then not to be had from ~zod.
    seams::take_synced_commits();
    assert!(opened.piece(1).is_err());
    assert!(seams::take_synced_commits() >= 1, "a piece was given up without a synced commit");
    drop(opened);
    let auth = ("Authorization", t.auth.as_str());
    let cut = http(&t.server, &content, &[auth]);
    assert!(cut.body.len() < data.len() && cut.body == data[..cut.body.len()], "a wrong byte, or the whole file");
    assert_eq!(http(&t.server, &one, &[auth]).status, 504);
    assert_eq!(kept_of(&t.b, "nec", &id).unwrap().1[1], None);
    consistent(&t.b, "nec");
}

/// Nothing a lying or stalling ship says is kept: a file is kept only once its length and
/// every hash have been checked against its id, and a piece only once it matches its hash; a
/// stream cut part way keeps what came whole and nothing else. (H1, rule 7)
#[test]
fn what_a_lying_ship_says_is_never_kept() {
    let t = two("liar-kept");
    let data = contents(2 * CHUNK as usize + 3, 4);
    let id = open_file(&t, &data, "");
    let info = || t.get(&t.path("counter", &id, ""), &[]).status;
    t.lie(|_, reply| {
        let mut lied = reply.clone();
        match &mut lied.body {
            Some(peer_reply::Body::FileAbout(facts)) => facts.length += 1,
            _ => return None,
        }
        Some(Lie::Reply(lied))
    });
    assert_eq!(info(), 502);
    t.lie(|_, reply| {
        let mut lied = reply.clone();
        match &mut lied.body {
            Some(peer_reply::Body::FileLeaves(sent)) => sent.hashes[0] ^= 1,
            _ => return None,
        }
        Some(Lie::Reply(lied))
    });
    assert_eq!(info(), 502);
    assert!(kept_of(&t.b, "nec", &id).is_none(), "a file was kept on hashes that were not its own");
    // A chunk with a wrong byte, one cut short, and one cut off altogether.
    t.lie(|body, reply| {
        let mut lied = reply.clone();
        match (chunk_asked(body), &mut lied.body) {
            (Some(0), Some(peer_reply::Body::FileChunk(sent))) => sent.data[7] ^= 1,
            (Some(1), Some(peer_reply::Body::FileChunk(sent))) => sent.data.truncate(10),
            (Some(2), _) => return Some(Lie::Cut),
            _ => return None,
        }
        Some(Lie::Reply(lied))
    });
    for n in 0..3 {
        let status = t.get(&t.path("counter", &id, &format!("/chunks/{n}")), &[]).status;
        assert!(matches!(status, 502 | 504), "{n}: {status}");
    }
    let short = t.get(&t.path("counter", &id, "/content"), &[]);
    assert!(short.body.is_empty() || short.body == data[..short.body.len()]);
    assert_eq!(kept_of(&t.b, "nec", &id).expect("kept once checked").1, vec![None, None, None]);
    consistent(&t.b, "nec");
    // Honest again: every piece is kept, and the file is exactly itself.
    t.honest();
    assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    held_soon(&t.b, "nec", &id, None);
    consistent(&t.b, "nec");
}

/// A failure at each step of keeping a piece leaves no row naming bytes that are missing, not
/// durable or not right; the piece read is passed on all the same; what the failure leaves on
/// disk goes with the kept file. (H1, H6, H7, rules 1, 4 and 7)
#[test]
fn a_failure_at_any_step_of_keeping_a_piece_names_nothing_wrong() {
    let t = two("keep-faults");
    let data = contents(2 * CHUNK as usize, 5);
    let id = open_file(&t, &data, "");
    let first = &data[..CHUNK as usize];
    // Bytes that are not the piece the row's hash stands for are never named.
    let dir = t.b.open_remote("nec", "zod", "counter", &id).unwrap().kept_dir().unwrap();
    let mut wrong = first.to_vec();
    wrong[3] ^= 1;
    assert!(matches!(t.b.keep_piece("nec", &id, &dir, data.len() as u64, 0, wrong), Err(Error::File(FileError::NotFound))));
    assert_eq!(kept_of(&t.b, "nec", &id).unwrap().1[0], None);
    assert!(on_disk(&b_files(&t))[&hex(&dir)].is_empty());
    // (seam, the piece is named after it, the commit's outcome is not known). A copy whose
    // commit's outcome is not known is a stray (R2): a file in the cache with one is thrown away
    // at once, with its directory, by the request that made it.
    let cases = [
        ("copy-create", false, false),
        ("copy-write", false, false),
        ("copy-sync", false, false),
        ("copy-dir-sync", false, false),
        ("chunk-commit", false, false),
        ("at-commit", false, true),
        ("commit-then-fail", true, true),
    ];
    for (point, named, unknown) in cases {
        t.b.kept_clear_all("nec").unwrap();
        let mut opened = t.b.open_remote("nec", "zod", "counter", &id).unwrap();
        let dir = opened.kept_dir().expect("kept");
        let (piece, fetched) = opened.piece(0).unwrap();
        assert!(fetched && piece == first, "{point}");
        seams::arm(point);
        assert!(opened.keep(0, piece.clone()).is_err(), "{point}: no failure");
        assert!(!seams::hit(point), "{point}: the seam was never reached");
        if unknown {
            assert!(kept_of(&t.b, "nec", &id).is_none(), "{point}: a cached file with a stray was kept");
            assert!(!b_files(&t).join(hex(&dir)).exists(), "{point}: its directory outlived it");
        } else {
            let (_, pieces) = kept_of(&t.b, "nec", &id).unwrap();
            assert_eq!(pieces[0].is_some(), named, "{point}");
            assert!(on_disk(&b_files(&t)).remove(&hex(&dir)).unwrap_or_default().is_empty(), "{point}");
        }
        consistent(&t.b, "nec");
        // Opening is no worse: the piece is had, exactly.
        assert_eq!(opened.piece(0).unwrap().0, first, "{point}");
    }
    // An unwind before the commit: the connection is closed, and the copy goes.
    t.b.kept_clear_all("nec").unwrap();
    let mut opened = t.b.open_remote("nec", "zod", "counter", &id).unwrap();
    let dir = opened.kept_dir().unwrap();
    let (piece, _) = opened.piece(0).unwrap();
    seams::arm("panic-before-commit");
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| opened.keep(0, piece))).is_err(), "inconclusive: nothing unwound");
    assert_eq!(kept_of(&t.b, "nec", &id).unwrap().1[0], None);
    assert!(on_disk(&b_files(&t)).remove(&hex(&dir)).unwrap_or_default().is_empty());
    drop(opened);
    consistent(&t.b, "nec");
    // A file being saved goes on after a commit of unknown outcome, and when it is saved the
    // copy no row names is swept.
    let saving = put(&t.a, "~zod", "counter", &contents(2 * CHUNK as usize, 15), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&saving)));
    let saving_data = contents(2 * CHUNK as usize, 15);
    let leaves: Vec<[u8; 32]> = saving_data.chunks(CHUNK as usize).map(files::leaf).collect();
    let dir = t.b.begin_keeping("nec", &saving, saving_data.len() as u64, "", &leaves, Some("counter")).unwrap();
    seams::arm("at-commit");
    assert!(t.b.keep_piece("nec", &saving, &dir, saving_data.len() as u64, 0, saving_data[..CHUNK as usize].to_vec()).is_err());
    assert!(kept_of(&t.b, "nec", &saving).unwrap().0.saving, "a file being saved was thrown away for a stray");
    assert_eq!(on_disk(&b_files(&t))[&hex(&dir)].len(), 1);
    assert!(t.b.save_file("nec", "counter", "zod", "counter", &saving).unwrap().done);
    let file = t.b.inner.with_ship("nec", |held| Ok(store::file_by_id(&lock(&held.conn), &saving)?)).unwrap().unwrap();
    assert_eq!(file.dir, dir, "the saved file is not in the kept file's directory");
    assert_eq!(on_disk(&b_files(&t))[&hex(&dir)].len(), 2, "a copy no row names outlived the save");
    assert!(t.b.file_chunk("nec", "counter", &saving, 0).unwrap() == saving_data[..CHUNK as usize]);
    assert_eq!(strays(&t.b, "nec", &dir), 0, "the strays of a directory become a file's were not forgotten");
    consistent(&t.b, "nec");
}

/// A piece is named only by the very kept file it was fetched for: one thrown away and kept
/// again meanwhile, under a new directory, never takes it, whether that happens before the
/// piece is fetched is done, before its name is made, or between its name and its commit.
/// (H10)
#[test]
fn a_piece_goes_only_into_the_kept_file_it_was_fetched_for() {
    let t = two("identity");
    let data = contents(2 * CHUNK as usize, 6);
    let id = open_file(&t, &data, "");
    let mut opened = t.b.open_remote("nec", "zod", "counter", &id).unwrap();
    let old = opened.kept_dir().unwrap();
    let (piece, _) = opened.piece(0).unwrap();
    assert_eq!(t.b.kept_clear("nec", &id).unwrap(), Cleared { thrown_away: 1, being_saved: 0 });
    let new = t.b.open_remote("nec", "zod", "counter", &id).unwrap().kept_dir().unwrap();
    assert_ne!(old, new);
    assert!(matches!(opened.keep(0, piece.clone()), Err(Error::File(FileError::NotFound))));
    assert_eq!(kept_of(&t.b, "nec", &id).unwrap().1, vec![None, None]);
    let disk = on_disk(&b_files(&t));
    assert!(!disk.contains_key(&hex(&old)) && disk[&hex(&new)].is_empty(), "{disk:?}");
    drop(opened);
    // Thrown away and kept again after the piece was looked up for, before its name is made.
    let mut opened = t.b.open_remote("nec", "zod", "counter", &id).unwrap();
    let (piece, _) = opened.piece(0).unwrap();
    let rt = t.b.clone();
    let newer = Arc::new(std::sync::Mutex::new(None));
    let noted = newer.clone();
    seams::on_before_create(move || {
        rt.kept_clear("nec", &id).unwrap();
        *noted.lock().unwrap() = rt.open_remote("nec", "zod", "counter", &id).ok().and_then(|opened| opened.kept_dir());
    });
    assert!(matches!(opened.keep(0, piece.clone()), Err(Error::File(FileError::NotFound))));
    let newer = newer.lock().unwrap().expect("inconclusive: not kept again in between");
    assert!(on_disk(&b_files(&t))[&hex(&newer)].is_empty());
    assert_eq!(kept_of(&t.b, "nec", &id).unwrap().1, vec![None, None]);
    drop(opened);
    // Between the name and the commit.
    let ready = t.b.prepare_copy("nec", &newer, 0, piece, Holder::Kept { id, length: data.len() as u64 }).unwrap();
    assert_eq!(on_disk(&b_files(&t))[&hex(&newer)].len(), 1);
    t.b.kept_clear("nec", &id).unwrap();
    let newest = t.b.open_remote("nec", "zod", "counter", &id).unwrap().kept_dir().unwrap();
    assert!(matches!(ready.commit(), Err(Error::File(FileError::NotFound))));
    assert!(on_disk(&b_files(&t))[&hex(&newest)].is_empty());
    assert_eq!(kept_of(&t.b, "nec", &id).unwrap().1, vec![None, None]);
    consistent(&t.b, "nec");
}

/// The cache stays within its allowance at every instant, throwing away the least recently
/// opened first, never the file being read; when it was last opened is written at most once a
/// minute; a file not opened for `cache_keep_millis` goes when the next keeping starts. (H5)
#[test]
fn the_cache_stays_within_its_allowance_least_recently_opened_first() {
    let most = 2 * CHUNK + CHUNK / 2;
    let t = two_with("lru", (fast(), NetConfig::default()), (Config { max_cache_bytes: most, ..fast() }, NetConfig::default()), &["~nec"]);
    let data: Vec<Vec<u8>> = (0..6).map(|seed| contents(CHUNK as usize, 10 + seed)).collect();
    let ids: Vec<[u8; 32]> = data.iter().map(|data| open_file(&t, data, "")).collect();
    let now = store::now_ms();
    for n in 0..2 {
        assert!(t.get(&t.path("counter", &ids[n], "/content"), &[]).body == data[n]);
        held_soon(&t.b, "nec", &ids[n], None);
    }
    // The second is the older of the two.
    sql(&t.b, "nec", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&ids[0][..], (now - 300_000) as i64]);
    sql(&t.b, "nec", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&ids[1][..], (now - 600_000) as i64]);
    assert!(t.get(&t.path("counter", &ids[2], "/content"), &[]).body == data[2]);
    held_soon(&t.b, "nec", &ids[2], None);
    assert!(kept_of(&t.b, "nec", &ids[1]).is_none(), "the least recently opened was not thrown away");
    assert_eq!(kept_of(&t.b, "nec", &ids[0]).unwrap().0.held, CHUNK);
    assert_eq!(kept_of(&t.b, "nec", &ids[2]).unwrap().0.held, CHUNK);
    consistent(&t.b, "nec");
    // Opened a minute or more after it was last written: written. Opened again at once: not.
    assert_eq!(t.get(&t.path("counter", &ids[0], ""), &[]).status, 200);
    let touched = kept_of(&t.b, "nec", &ids[0]).unwrap().0.used;
    assert!(touched >= now, "when it was opened was not brought up to date");
    sql(&t.b, "nec", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&ids[0][..], (touched - 30_000) as i64]);
    assert_eq!(t.get(&t.path("counter", &ids[0], ""), &[]).status, 200);
    assert_eq!(kept_of(&t.b, "nec", &ids[0]).unwrap().0.used, touched - 30_000, "written twice in a minute");
    // Not opened for longer than `cache_keep_millis`: thrown away when the next keeping starts.
    sql(&t.b, "nec", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&ids[2][..], (now - 31 * 24 * 3_600_000) as i64]);
    assert_eq!(t.get(&t.path("counter", &ids[3], ""), &[]).status, 200);
    assert!(kept_of(&t.b, "nec", &ids[2]).is_none(), "a stale kept file was not swept");
    // Many opening at once: sampled throughout, the cache is never over its allowance.
    let samples = std::thread::scope(|scope| {
        // Two at once: the most that may wait on other ships with the default workers.
        let openers: Vec<_> = (0..2)
            .map(|thread| {
                let (t, data, ids) = (&t, &data, &ids);
                scope.spawn(move || {
                    for round in 0..4 {
                        let n = (thread + round) % 6;
                        let got = t.get(&t.path("counter", &ids[n], "/content"), &[]);
                        assert!(got.status == 200 && got.body == data[n], "{n}: {}", got.status);
                    }
                })
            })
            .collect();
        let mut samples = Vec::new();
        while !openers.iter().all(|opener| opener.is_finished()) {
            let (held, removing, _) = t.b.cache_bytes("nec").unwrap();
            samples.push(held + removing);
        }
        for opener in openers {
            opener.join().unwrap();
        }
        samples
    });
    assert!(!samples.is_empty() && samples.iter().all(|bytes| *bytes <= most), "over the allowance: {:?}", samples.iter().max());
    consistent(&t.b, "nec");
}

/// The allowance lowered while the runtime was down: the least recently opened go, where
/// uploads are swept, until the cache is within it. (H5)
#[test]
fn a_lowered_allowance_is_kept_to_from_the_next_sweep() {
    let dir = TempDir::new("lowered");
    let rt = lone(&dir, fast());
    let (old, _) = keep_lone(&rt, "~zod", &contents(CHUNK as usize, 1));
    let (new, _) = keep_lone(&rt, "~zod", &contents(CHUNK as usize, 2));
    // Older than the other, and not stale: only the allowance can be why it goes.
    sql(&rt, "~zod", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&old[..], (store::now_ms() - 5_000) as i64]);
    drop(rt);
    let rt = Runtime::open(&dir.0, Config { max_cache_bytes: CHUNK + 10, ..fast() }).unwrap();
    rt.upload_start("~zod", "counter", 5, "").unwrap();
    assert!(kept_of(&rt, "~zod", &old).is_none() && kept_of(&rt, "~zod", &new).is_some());
    consistent(&rt, "~zod");
    // The same for the rows: two files of 8,192 chunks, each 1 MiB and 1 KiB of rows, kept with
    // 4 MiB for the cache's rows; then the ship's file lowered so that 2 MiB is.
    let rows = TempDir::new("lowered-rows");
    let rt = lone(&rows, Config { max_ship_bytes: 64 << 20, ..fast() });
    let length = 8192 * CHUNK;
    let wide: Vec<[u8; 32]> = (0..2u8)
        .map(|seed| {
            let leaves: Vec<[u8; 32]> = (0..8192u32).map(|n| files::leaf(&[&n.to_le_bytes()[..], &[seed]].concat())).collect();
            let id = files::file_id(length, &files::root(&leaves));
            rt.begin_keeping("~zod", &id, length, "", &leaves, None).unwrap();
            id
        })
        .collect();
    sql(&rt, "~zod", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&wide[0][..], (store::now_ms() - 5_000) as i64]);
    drop(rt);
    let rt = Runtime::open(&rows.0, Config { max_ship_bytes: 32 << 20, ..fast() }).unwrap();
    rt.upload_start("~zod", "counter", 5, "").unwrap();
    assert!(kept_of(&rt, "~zod", &wide[0]).is_none() && kept_of(&rt, "~zod", &wide[1]).is_some());
}

/// Making room throws away at most `THROW_FILES` kept files in one request: if that is not
/// enough, the piece is not kept. (H5)
#[test]
fn throwing_away_to_make_room_is_bounded() {
    let dir = TempDir::new("bounded-throw");
    let rt = lone(&dir, Config { max_cache_bytes: CHUNK, ..fast() });
    let small = THROW_FILES as usize + 6;
    for n in 0..small {
        keep_lone(&rt, "~zod", &[n as u8, (n >> 8) as u8 + 1]);
    }
    assert_eq!(kept_count(&rt, "~zod"), small);
    let big = contents(CHUNK as usize, 3);
    let id = files::id_of(&big);
    let dir = rt.begin_keeping("~zod", &id, CHUNK, "", &[files::leaf(&big)], None).unwrap();
    assert!(matches!(rt.keep_piece("~zod", &id, &dir, CHUNK, 0, big), Err(Error::File(FileError::NoRoom))));
    assert_eq!(kept_count(&rt, "~zod"), small - THROW_FILES as usize + 1);
    assert_eq!(kept_of(&rt, "~zod", &id).unwrap().1, vec![None]);
    consistent(&rt, "~zod");
    // And at most `THROW_ROWS` chunk rows: kept files of 32,768 chunks, one piece of each
    // held, are two rows past the budget for two of them.
    let wide = TempDir::new("bounded-rows");
    let rt = lone(&wide, Config { max_cache_bytes: 4 * CHUNK, max_ship_bytes: 4 << 30, ..fast() });
    let length = files::FANOUT as u64 * CHUNK;
    let mut wides = Vec::new();
    for seed in 0..4u8 {
        let piece = contents(CHUNK as usize, 50 + seed);
        let mut leaves: Vec<[u8; 32]> = (0..files::FANOUT as u32).map(|n| files::leaf(&[&n.to_le_bytes()[..], &[seed]].concat())).collect();
        leaves[0] = files::leaf(&piece);
        let id = files::file_id(length, &files::root(&leaves));
        let dir = rt.begin_keeping("~zod", &id, length, "", &leaves, None).unwrap();
        rt.keep_piece("~zod", &id, &dir, length, 0, piece).unwrap();
        wides.push(id);
    }
    assert_eq!(rt.cache_bytes("~zod").unwrap().0, 4 * CHUNK);
    // Room for four more pieces needs all four gone; two whole files of 32,768 chunks are all
    // one request's budget takes.
    rt.make_cache_room("zod", &[0; 32], 4 * CHUNK);
    assert_eq!(kept_count(&rt, "~zod"), 2);
    assert!(kept_of(&rt, "~zod", &wides[0]).is_none() && kept_of(&rt, "~zod", &wides[1]).is_none());
}

/// Held and reserved file bytes, saves in progress counted, stay within `max_file_bytes`; and
/// a save is refused, as an upload would be, for want of room or for too many files. (H5)
#[test]
fn saves_in_progress_count_against_the_file_allowance() {
    let cfg = Config { max_file_bytes: 3 * CHUNK, max_files: 2, save_slice_millis: 0, ..fast() };
    let t = two_with("allowance", (fast(), NetConfig::default()), (cfg, NetConfig::default()), &["~nec"]);
    let two_mib = open_file(&t, &contents(2 * CHUNK as usize, 1), "");
    let other = open_file(&t, &contents(2 * CHUNK as usize, 2), "");
    let one_mib = open_file(&t, &contents(CHUNK as usize, 3), "");
    let third = open_file(&t, &contents(10, 4), "");
    assert_eq!(save_reply(&save(&t, "counter", &two_mib)), (false, 0, 2));
    assert_eq!(t.b.file_bytes("nec").unwrap(), (0, 2 * CHUNK));
    assert!(matches!(t.b.upload_start("~nec", "counter", 2 * CHUNK, ""), Err(Error::File(FileError::NoRoom))));
    assert_eq!(save(&t, "counter", &other).status, 507);
    assert_eq!(save_reply(&save(&t, "counter", &one_mib)), (false, 0, 1));
    assert_eq!(t.b.file_bytes("nec").unwrap(), (0, 3 * CHUNK));
    // Two being saved, and at most two files: a third is refused.
    assert_eq!(save(&t, "counter", &third).status, 409);
    consistent(&t.b, "nec");
}

/// Kept files are at most `max_kept`: the least recently opened in the cache goes to make room
/// for another; when every one is being saved, another is opened and not kept. (H5, H7)
#[test]
fn kept_files_are_bounded_in_number() {
    let cfg = Config { max_kept: 2, save_slice_millis: 0, ..fast() };
    let t = two_with("count", (fast(), NetConfig::default()), (cfg, NetConfig::default()), &["~nec"]);
    let data: Vec<Vec<u8>> = (0..4).map(|seed| contents(100, seed)).collect();
    let ids: Vec<[u8; 32]> = data.iter().map(|data| open_file(&t, data, "")).collect();
    assert_eq!(t.get(&t.path("counter", &ids[0], ""), &[]).status, 200);
    // The older, and not stale: only the count can be why it goes.
    sql(&t.b, "nec", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&ids[0][..], (store::now_ms() - 5_000) as i64]);
    assert_eq!(t.get(&t.path("counter", &ids[1], ""), &[]).status, 200);
    assert_eq!(t.get(&t.path("counter", &ids[2], ""), &[]).status, 200);
    assert_eq!(kept_count(&t.b, "nec"), 2);
    assert!(kept_of(&t.b, "nec", &ids[0]).is_none());
    assert_eq!(save_reply(&save(&t, "counter", &ids[1])).0, false);
    assert_eq!(save_reply(&save(&t, "counter", &ids[2])).0, false);
    let opened = t.get(&t.path("counter", &ids[3], "/content"), &[]);
    assert!(opened.status == 200 && opened.body == data[3], "not keeping made opening worse");
    assert!(kept_of(&t.b, "nec", &ids[3]).is_none());
    assert_eq!(kept_count(&t.b, "nec"), 2);
}

/// A kept file's rows must fit the room the ship keeps in its own file, as an upload's must:
/// if they do not, it is not kept, and no directory is left. A file well under the cache's
/// allowance of rows, the ship's file filled until what is spare is less than the file's rows
/// (by the estimate) and the room kept for one command, and more than the rows really take:
/// refused by that check. (H5)
#[test]
fn a_kept_files_rows_must_fit_the_room_the_ship_keeps() {
    let chunks = 3000u32;
    let leaves: Vec<[u8; 32]> = (0..chunks).map(|n| files::leaf(&n.to_le_bytes())).collect();
    let length = u64::from(chunks) * CHUNK;
    let id = files::file_id(length, &files::root(&leaves));
    // Hashes that are not those of the id are refused before anything is looked at.
    let dir = TempDir::new("rows-room");
    let rt = lone(&dir, Config { max_ship_bytes: 16 << 20, ..fast() });
    let mut other = leaves.clone();
    other[5][0] ^= 1;
    assert!(matches!(rt.begin_keeping("~zod", &id, length, "", &other, None), Err(Error::File(FileError::Malformed(_)))));
    let estimate = files::rows_cost(u64::from(chunks));
    assert!(estimate < (16 << 20) / 16, "inconclusive: the file does not fit the cache's allowance of rows");
    let room = crate::ship::room_to_take_one(&rt.inner.cfg);
    // Spare left at the room kept plus three quarters of the estimate: the rows take less.
    let target = room + estimate * 3 / 4;
    let spare = || rt.inner.with_ship("~zod", |held| Ok(store::spare_bytes(&lock(&held.conn))?)).unwrap();
    let mut key = 0u32;
    for step in [256 << 10, 16 << 10, 2 << 10] {
        while spare() > target + step {
            key += 1;
            sql(&rt, "~zod", "INSERT INTO kv VALUES ('filler', ?1, zeroblob(?2))", params![key.to_le_bytes().to_vec(), step as i64]);
        }
    }
    let left = spare();
    assert!(left > room && left < room + estimate, "inconclusive: {left} spare, {room} kept, {estimate} the rows");
    assert!(matches!(rt.begin_keeping("~zod", &id, length, "", &leaves, None), Err(Error::File(FileError::NoRoom))));
    assert_eq!(kept_count(&rt, "~zod"), 0);
    assert!(on_disk(&dir.0.join("files/zod")).is_empty());
    // With room, the same is kept: every chunk's row, and no bytes.
    let roomy = TempDir::new("rows-roomy");
    let rt = lone(&roomy, fast());
    rt.begin_keeping("~zod", &id, length, "", &leaves, None).unwrap();
    assert_eq!(kept_of(&rt, "~zod", &id).unwrap().1.len(), chunks as usize);
}

/// One save call takes a bounded time, carries on where the last left off, and holds a place
/// among the downloads and among other ships' share of them for as long as it waits. (H5,
/// rule 5)
#[test]
fn a_save_call_is_bounded_and_carries_on_where_it_left_off() {
    let cfg = Config { save_slice_millis: 300, ..fast() };
    let t = two_with("slice", (fast(), NetConfig::default()), (cfg, quick()), &["~nec"]);
    let data = contents(4 * CHUNK as usize, 7);
    let id = open_file(&t, &data, "");
    // Each question for a chunk takes longer than the slice: so once one has begun, the slice
    // has run out before it ends, and the rule is that no new question is asked after that. A
    // call therefore asks for at most one chunk (none, if asking what the file is and beginning
    // to keep it spent the slice), and the next call carries on where it left off, asking for
    // no chunk twice. (No end-to-end time is asserted: local work is not bounded by the slice.)
    let chunks_asked = Arc::new(AtomicUsize::new(0));
    let counted = chunks_asked.clone();
    t.lie(move |body, _| {
        chunk_asked(body).map(|_| {
            counted.fetch_add(1, Ordering::SeqCst);
            Lie::Slow(Duration::from_millis(400))
        })
    });
    let (done, mut held, chunks) = save_reply(&save(&t, "counter", &id));
    assert!(!done && chunks == 4 && held <= 1, "{held}");
    assert!(chunks_asked.load(Ordering::SeqCst) <= 1, "a question was asked after the slice ran out");
    let listed = ship_proto::SaveList::decode(&*device(&t, "GET", "/ships/nec/agents/counter/files/saves").body).unwrap();
    assert_eq!((listed.saves.len(), listed.saves[0].chunks), (1, 4));
    let mut calls = 1;
    loop {
        let before = chunks_asked.load(Ordering::SeqCst);
        let (done, now, _) = save_reply(&save(&t, "counter", &id));
        assert!(chunks_asked.load(Ordering::SeqCst) - before <= 1, "a question was asked after the slice ran out");
        if done {
            break;
        }
        assert!(now >= held, "a call lost what an earlier one kept");
        held = now;
        calls += 1;
        assert!(calls < 40, "the save never finished");
    }
    assert_eq!(chunks_asked.load(Ordering::SeqCst), 4, "a chunk was asked for twice, or one never");
    let local = device(&t, "GET", &format!("/ships/nec/agents/counter/files/{}/content", hex(&id)));
    assert!(local.status == 200 && local.body == data);
    // Two saves waiting on ~zod hold both places other ships' files may have: a third request
    // for one is told to try again. Each save is held at its first question to ~zod (what the
    // file is), which it asks holding its places whatever its slice; counted, so as to wait until
    // both are there, never for a fixed time. On runtimes of their own whose network deadlines
    // are longer than the watchdogs here, so that the held saves cannot run out of time.
    drop(t);
    let t = two_with("slice-held", (fast(), held_net()), (Config { save_slice_millis: 300, ..fast() }, held_net()), &["~nec"]);
    let kept_one = open_file(&t, &contents(CHUNK as usize, 11), "");
    t.honest();
    assert_eq!(t.get(&t.path("counter", &kept_one, ""), &[]).status, 200);
    assert!(kept_of(&t.b, "nec", &kept_one).is_some());
    let (one, two) = (open_file(&t, &contents(CHUNK as usize, 8), ""), open_file(&t, &contents(CHUNK as usize, 9), ""));
    let unkept = open_file(&t, &contents(100, 10), "");
    let waiting = Arc::new(AtomicUsize::new(0));
    let count = waiting.clone();
    // Held by a barrier the test lets go after its assertions.
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let holding = gate.clone();
    t.lie(move |body, _| {
        matches!(body, peer_request::Body::FileAbout(_)).then(|| {
            count.fetch_add(1, Ordering::SeqCst);
            Lie::Held(holding.clone())
        })
    });
    std::thread::scope(|scope| {
        let saving: Vec<_> = [one, two].into_iter().map(|id| scope.spawn({
            let t = &t;
            move || save(t, "counter", &id).status
        })).collect();
        let until = Instant::now() + Duration::from_secs(20);
        while waiting.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < until, "inconclusive: the saves never waited on ~zod");
            std::thread::sleep(Duration::from_millis(10));
        }
        // A file not kept needs ~zod, and no place for waiting on it is free.
        let third = t.get(&t.path("counter", &unkept, ""), &[]);
        assert_eq!((third.status, third.header("Retry-After")), (503, Some("1")));
        // One that is kept is had all the same (what it is), asking nothing.
        assert_eq!(t.get(&t.path("counter", &kept_one, ""), &[]).status, 200);
        gate.close();
        for status in saving {
            assert_eq!(status.join().unwrap(), 200);
        }
    });
}

/// A saved file is an ordinary file of the ship's: closed, listed, downloadable with the other
/// ship gone, seen only through the agents that saved it, deletable, exported; under the kept
/// file's directory with no byte moved. A save of a file the ship holds asks nothing. A file
/// put on the ship while it was being saved is the one claimed. (H1, H2, H9)
#[test]
fn a_saved_file_is_an_ordinary_file_of_the_ship() {
    let t = two_with("saved", (fast(), NetConfig::default()), (fast(), quick()), &["~nec"]);
    let data = contents(2 * CHUNK as usize + 7, 8);
    let id = open_file(&t, &data, "image/png");
    assert_eq!(t.get(&t.path("counter", &id, "/chunks/0"), &[]).status, 200);
    held_soon(&t.b, "nec", &id, Some(0));
    let (kept, _) = kept_of(&t.b, "nec", &id).unwrap();
    seams::take_synced_commits();
    assert_eq!(save_reply(&save(&t, "counter", &id)), (true, 3, 3));
    assert!(kept_of(&t.b, "nec", &id).is_none());
    let info = t.b.file_info("~nec", "counter", &id).unwrap();
    assert_eq!((info.length, info.open, info.media_type.as_str()), (data.len() as u64, false, "image/png"));
    let file = t.b.inner.with_ship("nec", |held| Ok(store::file_by_id(&lock(&held.conn), &id)?)).unwrap().unwrap();
    assert_eq!(file.dir, kept.dir);
    assert_eq!(t.b.file_bytes("nec").unwrap(), (data.len() as u64, 0));
    assert_eq!(t.b.files("~nec", "counter", None, 10).unwrap().len(), 1);
    assert_eq!(say(&t.b, "~nec", "counter", &format!("file {}", hex(&id))), format!("{} 3 image/png", data.len()));
    assert_eq!(say(&t.b, "~nec", "keeper", &format!("file {}", hex(&id))), "none");
    assert_eq!(device(&t, "GET", &format!("/ships/nec/agents/keeper/files/{}", hex(&id))).status, 404);
    consistent(&t.b, "nec");
    // A second agent's save of a file the ship holds: claimed, nothing asked.
    let asked = counting(&t);
    assert_eq!(save_reply(&save(&t, "keeper", &id)), (true, 3, 3));
    assert_eq!(asked.load(Ordering::SeqCst), 0);
    // Exported with the ship, and brought in elsewhere whole.
    let out = TempDir::new("saved-out");
    t.b.set_recovery_key("~nec", seal::recovery_public("code-code")).unwrap();
    t.b.export_ship("~nec", &out.0).unwrap();
    let elsewhere = TempDir::new("saved-elsewhere");
    let other = Runtime::open(&elsewhere.0, fast()).unwrap();
    assert_eq!(other.import_ship_counted(&out.0, "~nec", "code-code").unwrap().kept, 1);
    let back: Vec<u8> = (0..3).flat_map(|n| other.file_chunk("~nec", "counter", &id, n).unwrap()).collect();
    assert!(back == data);
    // ~zod gone: still had.
    t.honest();
    drop(t.a_net);
    let local = http(&t.server, &format!("/ships/nec/agents/counter/files/{}/content", hex(&id)), &[("Authorization", &t.auth)]);
    assert!(local.status == 200 && local.body == data);
    // Deleted by both: gone from disk.
    t.b.file_delete("~nec", "counter", &id).unwrap();
    t.b.file_delete("~nec", "keeper", &id).unwrap();
    assert!(!t._dirs.1 .0.join("files/nec").join(hex(&kept.dir)).exists());
}

/// An identical file put on the ship while it is being saved: the save ends by claiming that
/// one, and the kept copy goes. (H1, H6)
#[test]
fn a_save_meets_a_file_put_on_the_ship_meanwhile() {
    let t = two("meanwhile");
    let data = contents(2 * CHUNK as usize, 9);
    let id = open_file(&t, &data, "");
    t.lie(|body, _| (chunk_asked(body) == Some(1)).then_some(Lie::Cut));
    let cut = save(&t, "counter", &id).status;
    assert!(matches!(cut, 502 | 504), "{cut}");
    let (kept, pieces) = kept_of(&t.b, "nec", &id).unwrap();
    assert!(kept.saving && pieces[0].is_some() && pieces[1].is_none());
    assert_eq!(put(&t.b, "~nec", "keeper", &data, ""), id);
    t.honest();
    assert_eq!(save_reply(&save(&t, "counter", &id)), (true, 2, 2));
    assert!(kept_of(&t.b, "nec", &id).is_none());
    assert!(!b_files(&t).join(hex(&kept.dir)).exists(), "the kept copy outlived the save");
    assert!(t.b.file_chunk("~nec", "counter", &id, 1).unwrap() == data[CHUNK as usize..]);
    assert_eq!(t.b.file_bytes("nec").unwrap(), (data.len() as u64, 0));
    consistent(&t.b, "nec");
}

/// Stopping a save returns its reservation; the file goes back to the cache if it fits there,
/// after others are thrown away to make room, and is thrown away if not; a save nobody calls
/// for `upload_keep_millis` stops. (H5, H6)
#[test]
fn stopping_a_save_returns_its_reservation() {
    let most = 2 * CHUNK + CHUNK / 2;
    let cfg = Config { max_cache_bytes: most, save_slice_millis: 0, ..fast() };
    let t = two_with("stop", (fast(), NetConfig::default()), (cfg, NetConfig::default()), &["~nec"]);
    let stop = |agent: &str, id: &[u8; 32]| device(&t, "DELETE", &format!("/ships/nec/agents/{agent}/files/saves/{}", hex(id))).status;
    let data = contents(2 * CHUNK as usize, 1);
    let id = open_file(&t, &data, "");
    assert_eq!(t.get(&t.path("counter", &id, "/chunks/0"), &[]).status, 200);
    held_soon(&t.b, "nec", &id, Some(0));
    assert_eq!(save_reply(&save(&t, "counter", &id)), (false, 1, 2));
    assert_eq!(t.b.cache_bytes("nec").unwrap(), (0, 0, 2 * CHUNK));
    assert_eq!(stop("keeper", &id), 404);
    assert_eq!(stop("counter", &[7; 32]), 404);
    assert_eq!(device(&t, "DELETE", "/ships/nec/agents/counter/files/saves/nothex").status, 404);
    assert_eq!(stop("counter", &id), 204);
    assert_eq!(t.b.cache_bytes("nec").unwrap(), (CHUNK, 0, 0));
    assert!(!kept_of(&t.b, "nec", &id).unwrap().0.saving);
    // Back to a full cache: the least recently opened other goes to make room.
    assert_eq!(save_reply(&save(&t, "counter", &id)).0, false);
    let others: Vec<[u8; 32]> = (0..2).map(|seed| open_file(&t, &contents(CHUNK as usize, 20 + seed), "")).collect();
    for other in &others {
        assert_eq!(t.get(&t.path("counter", other, "/content"), &[]).status, 200);
        held_soon(&t.b, "nec", other, None);
    }
    sql(&t.b, "nec", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&others[0][..], (store::now_ms() - 5_000) as i64]);
    assert_eq!(t.b.cache_bytes("nec").unwrap().0, 2 * CHUNK);
    assert_eq!(stop("counter", &id), 204);
    assert!(kept_of(&t.b, "nec", &others[0]).is_none() && kept_of(&t.b, "nec", &others[1]).is_some());
    assert_eq!(kept_of(&t.b, "nec", &id).unwrap().0.held, CHUNK);
    consistent(&t.b, "nec");
    // Wholly held and larger than the cache: thrown away when its save stops.
    let large = contents(3 * CHUNK as usize, 2);
    let large_id = open_file(&t, &large, "");
    assert_eq!(save_reply(&save(&t, "counter", &large_id)), (false, 0, 3));
    assert!(t.get(&t.path("counter", &large_id, "/content"), &[]).body == large);
    held_soon(&t.b, "nec", &large_id, None);
    assert_eq!(kept_of(&t.b, "nec", &large_id).unwrap().0.held, 3 * CHUNK);
    seams::take_synced_commits();
    t.b.save_stop("~nec", "counter", &large_id).unwrap();
    assert!(seams::take_synced_commits() >= 1);
    assert!(kept_of(&t.b, "nec", &large_id).is_none());
    assert_eq!(t.b.files_to_remove("nec").unwrap(), (0, 0));
    consistent(&t.b, "nec");
    // Not called for a day: stopped when the next upload starts.
    assert_eq!(save_reply(&save(&t, "counter", &id)).0, false);
    sql(&t.b, "nec", "UPDATE saves SET touched = 1", params![]);
    t.b.upload_start("~nec", "counter", 5, "").unwrap();
    assert!(t.b.saves("~nec", "counter").unwrap().is_empty());
    assert_eq!(t.b.file_bytes("nec").unwrap().1, 5);
}

/// Clearing clears: after it returns, no row names the cleared files, they are not read back,
/// and their bytes are gone once the trash drains; files being saved are untouched, and the
/// answer says so. A failure while clearing leaves rows naming only what is there. (H8, H6)
#[test]
fn clearing_clears_and_leaves_saves_alone() {
    let cfg = Config { save_slice_millis: 0, ..fast() };
    let t = two_with("clear", (fast(), NetConfig::default()), (cfg, NetConfig::default()), &["~nec"]);
    let data: Vec<Vec<u8>> = (0..4).map(|seed| contents(CHUNK as usize + 1, 30 + seed)).collect();
    let ids: Vec<[u8; 32]> = data.iter().map(|data| open_file(&t, data, "")).collect();
    for n in 0..3 {
        assert!(t.get(&t.path("counter", &ids[n], "/content"), &[]).body == data[n]);
        held_soon(&t.b, "nec", &ids[n], None);
    }
    // The fourth is being saved, and none of it held yet.
    assert_eq!(save_reply(&save(&t, "counter", &ids[3])), (false, 0, 2));
    let dirs: Vec<String> = ids.iter().map(|id| hex(&kept_of(&t.b, "nec", id).unwrap().0.dir)).collect();
    let cleared = |path: &str| {
        let answer = device(&t, "DELETE", path);
        assert_eq!(answer.status, 200, "{}", answer.text());
        let cleared = ship_proto::Cleared::decode(&*answer.body).unwrap();
        (cleared.thrown_away, cleared.being_saved)
    };
    assert_eq!(cleared(&format!("/ships/nec/files/kept/{}", hex(&ids[0]))), (1, 0));
    assert!(kept_of(&t.b, "nec", &ids[0]).is_none() && !b_files(&t).join(&dirs[0]).exists());
    assert_eq!(cleared(&format!("/ships/nec/files/kept/{}", hex(&ids[3]))), (0, 1));
    assert!(kept_of(&t.b, "nec", &ids[3]).unwrap().0.saving);
    assert_eq!(device(&t, "DELETE", &format!("/ships/nec/files/kept/{}", hex(&[5; 32]))).status, 404);
    assert_eq!(device(&t, "DELETE", "/ships/nec/files/kept/zz").status, 404);
    assert_eq!(cleared("/ships/nec/files/kept"), (2, 1));
    let listed = ship_proto::KeptList::decode(&*device(&t, "GET", "/ships/nec/files/kept").body).unwrap();
    assert_eq!(listed.kept.iter().map(|kept| kept.id.clone()).collect::<Vec<_>>(), vec![ids[3].to_vec()]);
    assert_eq!(on_disk(&b_files(&t)).into_keys().collect::<Vec<_>>(), vec![dirs[3].clone()]);
    assert_eq!(t.b.cache_bytes("nec").unwrap(), (0, 0, data[3].len() as u64));
    // Opened again, a cleared file is asked of ~zod afresh.
    let asked = counting(&t);
    assert!(t.get(&t.path("counter", &ids[1], "/content"), &[]).body == data[1]);
    assert!(asked.load(Ordering::SeqCst) > 0, "a cleared file was read back from ~nec");
    held_soon(&t.b, "nec", &ids[1], None);
    t.honest();
    // Removing the bytes fails: they stay counted against the cache, and go at the next try.
    let held = kept_of(&t.b, "nec", &ids[1]).unwrap().0.held;
    seams::arm("remove");
    seams::take_synced_commits();
    assert_eq!(t.b.kept_clear("nec", &ids[1]).unwrap(), Cleared { thrown_away: 1, being_saved: 0 });
    assert!(seams::take_synced_commits() >= 1, "thrown away without a synced commit");
    assert_eq!(t.b.cache_bytes("nec").unwrap().1, held);
    assert!(kept_of(&t.b, "nec", &ids[1]).is_none());
    assert_eq!(t.get(&t.path("counter", &ids[2], ""), &[]).status, 200);
    assert_eq!(t.b.cache_bytes("nec").unwrap().1, 0);
    // A clear that fails before its commit, or whose commit's outcome is unknown: the file is
    // still kept, and every row names bytes that are there.
    for point in ["throw-commit", "throw-uncertain"] {
        seams::arm(point);
        assert!(t.b.kept_clear("nec", &ids[2]).is_err(), "{point}");
        assert!(kept_of(&t.b, "nec", &ids[2]).is_some(), "{point}");
        consistent(&t.b, "nec");
    }
}

/// Only the owner's devices reach the cache and saves; names are checked; a kept file is never
/// served to another ship and no agent sees it. (H2)
#[test]
fn only_the_owners_devices_and_never_another_ship_or_agent() {
    let t = two("owners-kept");
    let data = contents(100, 1);
    let id = open_file(&t, &data, "");
    assert_eq!(t.get(&t.path("counter", &id, "/content"), &[]).status, 200);
    assert!(kept_of(&t.b, "nec", &id).is_some());
    let body = SaveRequest { ship: "~zod".into(), agent: "counter".into(), id: id.to_vec() }.encode_to_vec();
    for (method, path, body) in [
        ("GET", "/ships/nec/files/kept".to_string(), Vec::new()),
        ("DELETE", "/ships/nec/files/kept".to_string(), Vec::new()),
        ("DELETE", format!("/ships/nec/files/kept/{}", hex(&id)), Vec::new()),
        ("POST", "/ships/nec/agents/counter/files/save".to_string(), body.clone()),
        ("GET", "/ships/nec/agents/counter/files/saves".to_string(), Vec::new()),
        ("DELETE", format!("/ships/nec/agents/counter/files/saves/{}", hex(&id)), Vec::new()),
    ] {
        assert_eq!(request(&t.server, method, &path, &[], &body).status, 401, "{method} {path}");
        assert_eq!(request(&t.server, method, &path, &[("Authorization", "Bearer nonsense")], &body).status, 401, "{method} {path}");
    }
    assert!(kept_of(&t.b, "nec", &id).is_some(), "an unsigned request changed the cache");
    // The three routes of another ship's file, for a file kept: no device, no answer, and
    // nothing asked of ~zod.
    let asked = counting(&t);
    for rest in ["", "/chunks/0", "/content"] {
        let path = t.path("counter", &id, rest);
        assert_eq!(http(&t.server, &path, &[]).status, 401, "{rest}");
        assert_eq!(http(&t.server, &path, &[("Authorization", "Bearer nonsense")]).status, 401, "{rest}");
        assert_eq!(http(&t.server, &path, &[("Cookie", "ship_token=nonsense")]).status, 401, "{rest}");
    }
    assert_eq!(asked.load(Ordering::SeqCst), 0);
    t.honest();
    assert_eq!(request(&t.server, "PUT", "/ships/nec/files/kept", &[("Authorization", &t.auth)], b"").header("Allow"), Some("GET, DELETE"));
    assert_eq!(save(&t, "nobody", &id).status, 404);
    let bad = |ship: &str, agent: &str, id: Vec<u8>| {
        let body = SaveRequest { ship: ship.into(), agent: agent.into(), id }.encode_to_vec();
        request(&t.server, "POST", "/ships/nec/agents/counter/files/save", &[("Authorization", &t.auth)], &body).status
    };
    assert_eq!(bad("~nec", "counter", id.to_vec()), 400);
    assert_eq!(bad("Zod", "counter", id.to_vec()), 400);
    assert_eq!(bad("../zod", "counter", id.to_vec()), 400);
    assert_eq!(bad("~zod", "Counter", id.to_vec()), 400);
    assert_eq!(bad("~zod", "counter", id[..31].to_vec()), 400);
    assert_eq!(request(&t.server, "POST", "/ships/nec/agents/counter/files/save", &[("Authorization", &t.auth)], b"\xff\xff").status, 400);
    // Never to another ship, under any agent, here or over the wire.
    for agent in ["counter", "keeper", "tally"] {
        assert_eq!(t.b.serve_file("~nec", "~zod", agent, &id, Part::About, &WAITING).unwrap(), Served::Denied, "{agent}");
        assert_eq!(t.b.serve_file("~nec", "~zod", agent, &id, Part::Chunk(0), &WAITING).unwrap(), Served::Denied, "{agent}");
    }
    let wanted = FileWanted { agent: "counter".into(), id: id.to_vec(), index: 0 };
    match t.a.ask_for_file("~zod", "~nec", PeerRequest { body: Some(peer_request::Body::FileAbout(wanted)) }).unwrap() {
        Ok(PeerReply { body: Some(peer_reply::Body::FileAbout(facts)), .. }) => assert!(!facts.denied.is_empty()),
        other => panic!("{other:?}"),
    }
    // No agent sees it.
    for agent in ["counter", "keeper"] {
        assert_eq!(say(&t.b, "~nec", agent, &format!("file {}", hex(&id))), "none");
    }
}

/// Nothing readable on disk: kept and saved pieces are sealed as chunks are, and no content,
/// id, media type or source ship appears outside the ship's own file; a piece moved to
/// another place does not open. (H3)
#[test]
fn nothing_readable_on_disk_of_what_was_kept() {
    let t = two("sealed");
    let marker = b"A-PLAIN-MARKER-THAT-MUST-NEVER-SHOW";
    let data: Vec<u8> = marker.iter().cycle().take(CHUNK as usize + 100).copied().collect();
    let saved_data: Vec<u8> = marker.iter().rev().cycle().take(500).copied().collect();
    let id = open_file(&t, &data, "image/webp");
    let saved = open_file(&t, &saved_data, "image/webp");
    assert_eq!(t.get(&t.path("counter", &id, "/content"), &[]).status, 200);
    held_soon(&t.b, "nec", &id, None);
    assert_eq!(save_reply(&save(&t, "counter", &saved)).0, true);
    let mut seen = 0;
    let mut stack = vec![b_files(&t)];
    while let Some(path) = stack.pop() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!name.contains(&hex(&id)) && !name.contains(&hex(&saved)), "{name}");
        if path.is_dir() {
            stack.extend(fs::read_dir(&path).unwrap().map(|entry| entry.unwrap().path()));
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        seen += 1;
        // (The ship it came from is not stored anywhere, so is not looked for: a name of three
        // letters would turn up in a megabyte of ciphertext by chance.)
        for needle in [&marker[..12], &id[..], &saved[..], hex(&id).as_bytes(), b"image/webp"] {
            assert!(!bytes.windows(needle.len()).any(|window| window == needle), "{path:?} shows {needle:?}");
        }
    }
    assert!(seen >= 3, "inconclusive: only {seen} files on disk");
    // A piece copied to another chunk's place does not open there.
    let (kept, pieces) = kept_of(&t.b, "nec", &id).unwrap();
    let place = b_files(&t).join(hex(&kept.dir));
    let gen = pieces[0].unwrap();
    fs::copy(place.join(format!("0.{}", hex(&gen))), place.join(format!("1.{}", hex(&gen)))).unwrap();
    let hash = files::leaf(&data[..CHUNK as usize]);
    assert!(matches!(t.b.inner.read_copy("nec", &kept.dir, 0, &gen, CHUNK, &hash), files::ReadBack::Good(_)));
    assert_eq!(t.b.inner.read_copy("nec", &kept.dir, 1, &gen, CHUNK, &hash), files::ReadBack::Bad);
    fs::remove_file(place.join(format!("1.{}", hex(&gen)))).unwrap();
}

/// A kept file's answers carry every header a file's do, and its media type is kept as the
/// check at upload makes it. (H4)
#[test]
fn a_kept_files_answers_carry_the_file_headers() {
    let t = two("headers-kept");
    let picture = open_file(&t, &contents(30, 1), "image/png");
    let page = open_file(&t, &contents(40, 2), "");
    let picture_hex = hex(&picture);
    t.lie(move |body, reply| {
        let mut lied = reply.clone();
        let asked = match body {
            peer_request::Body::FileAbout(wanted) => hex(&wanted.id),
            _ => return None,
        };
        if let Some(peer_reply::Body::FileAbout(facts)) = &mut lied.body {
            facts.media_type = if asked == picture_hex { "IMAGE/PNG".into() } else { "text/html; charset=utf-8".into() };
        }
        Some(Lie::Reply(lied))
    });
    assert_eq!(t.get(&t.path("counter", &picture, "/content"), &[]).status, 200);
    assert_eq!(t.get(&t.path("counter", &page, "/content"), &[]).status, 200);
    held_soon(&t.b, "nec", &picture, None);
    held_soon(&t.b, "nec", &page, None);
    assert_eq!(kept_of(&t.b, "nec", &picture).unwrap().0.media_type, "image/png");
    assert_eq!(kept_of(&t.b, "nec", &page).unwrap().0.media_type, "application/octet-stream");
    // Now from what ~nec keeps, nothing asked.
    let asked = counting(&t);
    let shown = t.get(&t.path("counter", &picture, "/content"), &[]);
    kept_from_acting(&shown);
    assert_eq!((shown.header("Content-Type"), shown.header("Content-Disposition")), (Some("image/png"), Some("inline")));
    let saved = t.get(&t.path("counter", &page, "/content"), &[]);
    kept_from_acting(&saved);
    assert_eq!((saved.header("Content-Type"), saved.header("Content-Disposition")), (Some("application/octet-stream"), Some("attachment")));
    let chunk = t.get(&t.path("counter", &picture, "/chunks/0"), &[]);
    kept_from_acting(&chunk);
    assert_eq!((chunk.header("Content-Type"), chunk.header("Content-Disposition")), (Some("application/octet-stream"), Some("attachment")));
    let listed = device(&t, "GET", "/ships/nec/files/kept");
    assert_eq!(listed.header("X-Content-Type-Options"), Some("nosniff"));
    assert_eq!(asked.load(Ordering::SeqCst), 0);
}

/// The first look counts a kept file's directory as named: after a restart, a kept file and
/// its pieces are still there, and a directory no row names is gone. (H6)
#[test]
fn the_first_look_counts_a_kept_files_directory_as_named() {
    let dir = TempDir::new("first-look");
    let rt = lone(&dir, fast());
    let data = contents(2 * CHUNK as usize, 1);
    seams::take_synced_commits();
    let (id, kept) = keep_lone(&rt, "~zod", &data);
    assert!(seams::take_synced_commits() >= 3, "kept without synced commits");
    drop(rt);
    let stray = dir.0.join("files/zod").join("0f".repeat(16));
    fs::create_dir(&stray).unwrap();
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    assert_eq!(rt.kept("~zod", None, 10).unwrap().len(), 1);
    assert!(!stray.exists(), "a directory no row names outlived the first look");
    assert_eq!(on_disk(&dir.0.join("files/zod"))[&hex(&kept)].len(), 2);
    assert_eq!(kept_of(&rt, "~zod", &id).unwrap().0.held, data.len() as u64);
    consistent(&rt, "~zod");
}

/// What a failure while beginning to keep a file, or while throwing one away, leaves is
/// harmless and gets cleared. (H6)
#[test]
fn leftovers_of_keeping_and_throwing_away_are_cleared() {
    let dir = TempDir::new("leftovers");
    let rt = lone(&dir, fast());
    let data = contents(100, 2);
    let (leaves, id) = (vec![files::leaf(&data)], files::id_of(&data));
    keep_lone(&rt, "~zod", &contents(10, 9));
    let before = on_disk(&dir.0.join("files/zod"));
    // Certainly not kept, after its directory was made: the directory goes.
    seams::arm("kept-begin");
    assert!(rt.begin_keeping("~zod", &id, 100, "", &leaves, None).is_err());
    assert!(kept_of(&rt, "~zod", &id).is_none());
    assert_eq!(on_disk(&dir.0.join("files/zod")), before);
    // A commit of unknown outcome: the directory is left, and goes at the first look.
    seams::arm("at-commit");
    assert!(rt.begin_keeping("~zod", &id, 100, "", &leaves, None).is_err());
    assert!(kept_of(&rt, "~zod", &id).is_none());
    assert_eq!(on_disk(&dir.0.join("files/zod")).len(), before.len() + 1);
    drop(rt);
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    assert_eq!(rt.kept("~zod", None, 10).unwrap().len(), 1);
    assert_eq!(on_disk(&dir.0.join("files/zod")), before);
    // A commit that lands and then reports a failure: kept, and its directory with it.
    seams::arm("commit-then-fail");
    assert!(rt.begin_keeping("~zod", &id, 100, "", &leaves, None).is_err());
    let (kept, _) = kept_of(&rt, "~zod", &id).unwrap();
    assert!(dir.0.join("files/zod").join(hex(&kept.dir)).exists());
    rt.keep_piece("~zod", &id, &kept.dir, 100, 0, data.clone()).unwrap();
    consistent(&rt, "~zod");
    // Thrown away, and syncing where it was fails: the record stays, counted, until it is done.
    seams::arm("drain-sync");
    rt.kept_clear("~zod", &id).unwrap();
    assert!(!dir.0.join("files/zod").join(hex(&kept.dir)).exists());
    assert_eq!(rt.cache_bytes("~zod").unwrap().1, 100);
    assert_eq!(rt.files_to_remove("~zod").unwrap(), (100, 1));
    rt.upload_start("~zod", "counter", 5, "").unwrap();
    assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
    consistent(&rt, "~zod");
}

/// A failure while turning a kept file into a saved one, before its commit, at a commit of
/// unknown outcome, or after a commit that landed: no row names wrong bytes, and the next call
/// finishes. (H1, H6, rule 7)
#[test]
fn a_failure_while_saving_is_finished_by_the_next_call() {
    let t = two("save-faults");
    for (n, point) in ["save-commit", "save-uncertain", "save-then-fail"].into_iter().enumerate() {
        let data = contents(2 * CHUNK as usize + 1 + n, 40 + n as u8);
        let id = open_file(&t, &data, "");
        assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
        held_soon(&t.b, "nec", &id, None);
        let dir = kept_of(&t.b, "nec", &id).unwrap().0.dir;
        seams::arm(point);
        assert!(t.b.save_file("nec", "counter", "zod", "counter", &id).is_err(), "{point}");
        assert!(!seams::hit(point), "{point}: never reached");
        let file = t.b.inner.with_ship("nec", |held| Ok(store::file_by_id(&lock(&held.conn), &id)?)).unwrap();
        assert_eq!(file.is_some(), point == "save-then-fail", "{point}");
        assert_eq!(kept_of(&t.b, "nec", &id).is_some(), point != "save-then-fail", "{point}");
        consistent(&t.b, "nec");
        seams::take_synced_commits();
        let state = t.b.save_file("nec", "counter", "zod", "counter", &id).unwrap();
        // The first transaction of the call, and the one that makes the file (none for the one
        // already made).
        let synced = if point == "save-then-fail" { 1 } else { 2 };
        assert!(state.done && seams::take_synced_commits() >= synced, "{point}");
        assert!(kept_of(&t.b, "nec", &id).is_none());
        assert!(t.b.file_chunk("nec", "counter", &id, 2).unwrap() == data[2 * CHUNK as usize..], "{point}");
        assert_eq!(on_disk(&b_files(&t))[&hex(&dir)].len(), 3, "{point}");
        consistent(&t.b, "nec");
    }
}

/// Kept files and saves are neither exported nor imported, and an import validates nothing of
/// what it does not bring in: rows of them that make no sense refuse nothing. (H9)
#[test]
fn kept_files_and_saves_are_not_imported() {
    let (a, b, out) = (TempDir::new("import-a"), TempDir::new("import-b"), TempDir::new("import-out"));
    let rt = lone(&a, fast());
    let file = put(&rt, "~zod", "counter", &contents(30, 1), "");
    keep_lone(&rt, "~zod", &contents(20, 2));
    sql(&rt, "~zod", "INSERT INTO kept VALUES (x'01', x'02', -5, 'Not A Type', 0, 99)", params![]);
    sql(&rt, "~zod", "INSERT INTO kept_chunks VALUES (x'03', 0, x'', NULL)", params![]);
    sql(&rt, "~zod", "INSERT INTO saves VALUES (x'01', 'Not An Agent!', -1)", params![]);
    rt.set_recovery_key("~zod", seal::recovery_public("code-code")).unwrap();
    rt.export_ship("~zod", &out.0).unwrap();
    // The rows are in the sealed copy, as `uploads` are (R9): opened with the code, the copy of
    // the ship's file holds them.
    let sealed = fs::read(out.0.join("zod.ship")).unwrap();
    let (_, plain) = seal::open_export("code-code", "zod", sealed).expect("the copy opens");
    let inside = out.0.join("inside.sqlite");
    fs::write(&inside, plain).unwrap();
    let copy = rusqlite::Connection::open(&inside).unwrap();
    let count = |table: &str| copy.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!((count("kept"), count("kept_chunks"), count("saves")), (2, 2, 1));
    drop(copy);
    fs::remove_file(&inside).unwrap();
    let other = Runtime::open(&b.0, fast()).unwrap();
    assert_eq!(other.import_ship_counted(&out.0, "~zod", "code-code").unwrap().kept, 1);
    assert!(other.kept("~zod", None, 10).unwrap().is_empty());
    assert!(other.saves("~zod", "counter").unwrap().is_empty());
    assert_eq!(other.cache_bytes("~zod").unwrap(), (0, 0, 0));
    assert_eq!(other.file_chunk("~zod", "counter", &file, 0).unwrap(), contents(30, 1));
    assert_eq!(on_disk(&b.0.join("files/zod")).len(), 1);
}

/// With keeping off, opening another ship's file keeps nothing, as in part 2; a save still
/// works. (H9)
#[test]
fn with_keeping_off_nothing_is_kept_and_a_save_still_works() {
    let t = two_uncached("off");
    let data = contents(CHUNK as usize + 9, 3);
    let id = open_file(&t, &data, "");
    for _ in 0..2 {
        assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    }
    assert_eq!(kept_count(&t.b, "nec"), 0);
    assert!(on_disk(&b_files(&t)).is_empty());
    assert_eq!(save_reply(&save(&t, "counter", &id)), (true, 2, 2));
    assert!(t.b.file_chunk("nec", "counter", &id, 1).unwrap() == data[CHUNK as usize..]);
    assert_eq!(kept_count(&t.b, "nec"), 0);
    consistent(&t.b, "nec");
}

/// A kept file's rows are believed only as far as the id vouches for them: rows whose hashes
/// no longer come to the id are not read from and not kept into, and the file is opened as
/// part 2 opens it. (H1)
#[test]
fn a_kept_files_rows_are_believed_only_as_the_id_vouches() {
    let t = two("rows-vouched");
    let data = contents(2 * CHUNK as usize, 11);
    let id = open_file(&t, &data, "");
    assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    held_soon(&t.b, "nec", &id, None);
    let (kept, _) = kept_of(&t.b, "nec", &id).unwrap();
    // One hash changed in the ship's own file, and when it was opened set long ago.
    sql(&t.b, "nec", "UPDATE kept_chunks SET hash = ?2 WHERE dir = ?1 AND n = 1", params![&kept.dir[..], &[7u8; 32][..]]);
    // Older than a minute (so it would be written if it were believed), not stale.
    sql(&t.b, "nec", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&id[..], (store::now_ms() - 120_000) as i64]);
    // Kept already under rows that are not these hashes: never kept into.
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(files::leaf).collect();
    assert!(matches!(t.b.begin_keeping("nec", &id, data.len() as u64, "", &leaves, None), Err(Error::File(FileError::Damaged))));
    // Not believed: the file in the cache is certainly unusable, and is thrown away by the
    // ordinary path; the open goes to ~zod, and the file is kept afresh, in a new directory.
    let mut opened = t.b.open_remote("nec", "zod", "counter", &id).unwrap();
    let fresh = opened.kept_dir().expect("kept afresh");
    assert_ne!(fresh, kept.dir, "rows not vouched for were used");
    assert!(!b_files(&t).join(hex(&kept.dir)).exists(), "the unusable kept file's directory was left");
    assert!(opened.piece(1).unwrap().0 == data[CHUNK as usize..]);
    drop(opened);
    let again = t.get(&t.path("counter", &id, "/content"), &[]);
    assert!(again.status == 200 && again.body == data, "{}", again.status);
    consistent(&t.b, "nec");
    // A file being saved with rows that do not vouch: left, never touched, and its save calls
    // answer that it is damaged.
    let saving = open_file(&t, &contents(CHUNK as usize + 3, 21), "");
    let leaves: Vec<[u8; 32]> = contents(CHUNK as usize + 3, 21).chunks(CHUNK as usize).map(files::leaf).collect();
    let dir = t.b.begin_keeping("nec", &saving, CHUNK + 3, "", &leaves, Some("counter")).unwrap();
    sql(&t.b, "nec", "UPDATE kept_chunks SET hash = ?2 WHERE dir = ?1 AND n = 0", params![&dir[..], &[7u8; 32][..]]);
    let long_ago = store::now_ms() - 120_000;
    sql(&t.b, "nec", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&saving[..], long_ago as i64]);
    assert_eq!(t.get(&t.path("counter", &saving, ""), &[]).status, 200);
    let (kept, _) = kept_of(&t.b, "nec", &saving).expect("a file being saved is never thrown away for this");
    assert_eq!((kept.used, kept.saving), (long_ago, true), "touched before its rows were checked");
    assert_eq!(save(&t, "counter", &saving).status, 500);
}

/// What was thrown away from the cache counts against it until it is gone from disk. (H5)
#[test]
fn what_was_thrown_away_counts_against_the_cache_until_it_is_gone() {
    let dir = TempDir::new("trash-counts");
    let rt = lone(&dir, Config { max_cache_bytes: 150, ..fast() });
    let (first, _) = keep_lone(&rt, "~zod", &contents(100, 1));
    seams::arm("remove");
    rt.kept_clear("~zod", &first).unwrap();
    assert_eq!(rt.cache_bytes("~zod").unwrap(), (0, 100, 0));
    let next = contents(100, 2);
    let id = files::id_of(&next);
    // Beginning to keep drains the trash: that removal fails too.
    seams::arm("remove");
    let kept = rt.begin_keeping("~zod", &id, 100, "", &[files::leaf(&next)], None).unwrap();
    assert_eq!(rt.cache_bytes("~zod").unwrap(), (0, 100, 0), "inconclusive: the trash was drained");
    // Making room drains the trash too: that removal fails as well, and the piece is refused.
    seams::arm("remove");
    assert!(matches!(rt.keep_piece("~zod", &id, &kept, 100, 0, next.clone()), Err(Error::File(FileError::NoRoom))));
    assert_eq!(kept_of(&rt, "~zod", &id).unwrap().1, vec![None]);
    // Once it is gone, there is room.
    rt.upload_start("~zod", "counter", 5, "").unwrap();
    assert_eq!(rt.cache_bytes("~zod").unwrap().1, 0);
    rt.keep_piece("~zod", &id, &kept, 100, 0, next).unwrap();
    consistent(&rt, "~zod");
}

/// The file being read is never thrown away to make room for its own piece, even when it is the
/// least recently opened. (H5, H7)
#[test]
fn the_file_being_read_is_never_thrown_away_to_make_room() {
    let dir = TempDir::new("not-itself");
    let rt = lone(&dir, Config { max_cache_bytes: 2 * CHUNK + CHUNK / 2, ..fast() });
    let (other, _) = keep_lone(&rt, "~zod", &contents(CHUNK as usize, 1));
    let data = contents(2 * CHUNK as usize, 2);
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(files::leaf).collect();
    let id = files::id_of(&data);
    let kept = rt.begin_keeping("~zod", &id, data.len() as u64, "", &leaves, None).unwrap();
    rt.keep_piece("~zod", &id, &kept, data.len() as u64, 0, data[..CHUNK as usize].to_vec()).unwrap();
    sql(&rt, "~zod", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&id[..], (store::now_ms() - 5_000) as i64]);
    rt.keep_piece("~zod", &id, &kept, data.len() as u64, 1, data[CHUNK as usize..].to_vec()).unwrap();
    assert!(kept_of(&rt, "~zod", &other).is_none());
    assert_eq!(kept_of(&rt, "~zod", &id).unwrap().0.held, 2 * CHUNK);
    consistent(&rt, "~zod");
}

/// A piece that cannot be kept (here, the cache is smaller than a piece) is passed on all the
/// same, whole and by chunk. (H7, rule 4)
#[test]
fn a_piece_that_cannot_be_kept_is_passed_on_all_the_same() {
    let t = two_with("unkept", (fast(), NetConfig::default()), (Config { max_cache_bytes: 1000, ..fast() }, NetConfig::default()), &["~nec"]);
    let data = contents(2 * CHUNK as usize, 12);
    let id = open_file(&t, &data, "");
    let whole = t.get(&t.path("counter", &id, "/content"), &[]);
    assert!(whole.status == 200 && whole.body == data);
    let chunk = t.get(&t.path("counter", &id, "/chunks/1"), &[]);
    assert!(chunk.status == 200 && chunk.body == data[CHUNK as usize..]);
    assert_eq!(kept_of(&t.b, "nec", &id).expect("its rows are kept").1, vec![None, None]);
}

/// With keeping off, a file left in the cache from before is not read from; one being saved
/// still is. (H9)
#[test]
fn with_keeping_off_a_file_in_the_cache_is_not_read() {
    let dir = TempDir::new("off-cached");
    let rt = lone(&dir, fast());
    let (cached, _) = keep_lone(&rt, "~zod", &contents(100, 1));
    let saving = contents(200, 2);
    let id = files::id_of(&saving);
    let kept = rt.begin_keeping("~zod", &id, 200, "", &[files::leaf(&saving)], Some("counter")).unwrap();
    rt.keep_piece("~zod", &id, &kept, 200, 0, saving.clone()).unwrap();
    drop(rt);
    let rt = Runtime::open(&dir.0, Config { max_cache_bytes: 0, ..fast() }).unwrap();
    // No network here: a file read from what is kept needs none, and any other fails.
    assert!(rt.open_remote("zod", "nec", "counter", &cached).is_err(), "a cached file was read with keeping off");
    let mut opened = rt.open_remote("zod", "nec", "counter", &id).expect("a file being saved is read");
    assert_eq!(opened.piece(0).unwrap(), (saving, false));
}

/// The rows of files in the cache have their own allowance, a sixteenth of the ship's file:
/// opens that only learn what files are (the shape of a ship that lies about lengths, here
/// driven through the same call the route makes once part 2's checks pass, since the test liar
/// can only stand in for parts the asked ship allows) never take more, the least recently
/// opened go first, and an ordinary upload still starts after. A file whose own rows pass the
/// allowance is never kept in the cache. (R1, H5)
#[test]
fn the_rows_of_files_in_the_cache_have_their_own_allowance() {
    // 160 MiB of ship file: 10 MiB for the cache's rows, two files of 32,768 chunks.
    let most = 160 << 20;
    let dir = TempDir::new("rows-allowance");
    let rt = lone(&dir, Config { max_ship_bytes: most, ..fast() });
    let length = files::FANOUT as u64 * CHUNK;
    let made_up: Vec<([u8; 32], Vec<[u8; 32]>)> = (0..4u8)
        .map(|seed| {
            let leaves: Vec<[u8; 32]> = (0..files::FANOUT as u32).map(|n| files::leaf(&[&n.to_le_bytes()[..], &[seed]].concat())).collect();
            (files::file_id(length, &files::root(&leaves)), leaves)
        })
        .collect();
    let allowance = most / 16;
    for (n, (id, leaves)) in made_up.iter().enumerate() {
        rt.begin_keeping("~zod", id, length, "", leaves, None).unwrap();
        let rows = rt.cache_rows("~zod").unwrap();
        assert!(rows <= allowance, "{n}: the cache's rows take {rows}, over {allowance}");
        // Each a little older than the next.
        sql(&rt, "~zod", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&id[..], (store::now_ms() - 60_000 + n as u64 * 1_000) as i64]);
    }
    assert_eq!(kept_count(&rt, "~zod"), 2);
    assert!(kept_of(&rt, "~zod", &made_up[0].0).is_none() && kept_of(&rt, "~zod", &made_up[1].0).is_none(), "not the oldest went");
    let (upload, _) = rt.upload_start("~zod", "counter", CHUNK, "").unwrap();
    rt.upload_chunk("~zod", "counter", &upload, 0, contents(CHUNK as usize, 1)).unwrap();
    rt.upload_finish("~zod", "counter", &upload, None).unwrap();
    // A file whose own rows pass the allowance is never kept in the cache.
    // Refused at once: nothing else in the cache is thrown away for it.
    let narrow = TempDir::new("rows-too-wide");
    let rt = lone(&narrow, Config { max_ship_bytes: 32 << 20, ..fast() });
    let (small, _) = keep_lone(&rt, "~zod", &contents(100, 3));
    let (id, leaves) = &made_up[0];
    assert!(matches!(rt.begin_keeping("~zod", id, length, "", leaves, None), Err(Error::File(FileError::NoRoom))));
    assert_eq!(kept_count(&rt, "~zod"), 1);
    assert!(kept_of(&rt, "~zod", &small).is_some(), "a file was thrown away for one that could never fit");
}

/// Copies a crash left in a kept directory, named by no row and recorded nowhere, go the first
/// time a copy is made in that directory in a runtime's life; nothing a row names, and nothing
/// the trash records, is touched. A look whose listing fails removes nothing, and the directory
/// is not looked at again in that life: what it left stays through later keeps there, until the
/// next life's first copy. (R2, R14, H6)
#[test]
fn copies_a_crash_left_go_at_the_next_keep_into_their_directory() {
    let dir = TempDir::new("crash-left");
    let rt = lone(&dir, fast());
    let data = contents(4 * CHUNK as usize, 1);
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(files::leaf).collect();
    let id = files::id_of(&data);
    let length = data.len() as u64;
    let piece = |n: usize| data[n * CHUNK as usize..(n + 1) * CHUNK as usize].to_vec();
    let kept = rt.begin_keeping("~zod", &id, length, "", &leaves, None).unwrap();
    rt.keep_piece("~zod", &id, &kept, length, 0, piece(0)).unwrap();
    drop(rt);
    // As a crash between writing a copy and naming it leaves, and a copy given up whose removal
    // has yet to happen.
    let place = dir.0.join("files/zod").join(hex(&kept));
    let (left, recorded) = (place.join(format!("1.{}", "ab".repeat(16))), place.join(format!("1.{}", "cd".repeat(16))));
    fs::write(&left, b"left by a crash").unwrap();
    fs::write(&recorded, b"waiting to be removed").unwrap();
    let named = on_disk(&dir.0.join("files/zod"))[&hex(&kept)].iter().find(|name| name.starts_with("0.")).cloned().unwrap();
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    // Woken first, so that the first wake's drain is done before the trash records the copy.
    rt.kept("~zod", None, 1).unwrap();
    sql(&rt, "~zod", "INSERT INTO file_trash VALUES (?1, 1, ?2, 15, 1)", params![&kept[..], &[0xcdu8; 16][..]]);
    // What the look removes and leaves.
    rt.inner.with_ship("~zod", |held| {
        rt.inner.look("zod", &kept, &lock(&held.conn));
        Ok(())
    }).unwrap();
    assert!(!left.exists(), "a copy no row names outlived the look");
    assert!(recorded.exists(), "a copy the trash records was removed by the look");
    assert!(place.join(&named).exists(), "a copy a row names was removed");
    drop(rt);
    // A new life, and its first keep there: its look's listing fails. Nothing is removed, and
    // the directory is not looked through again in this life, whatever keeps follow.
    fs::write(&left, b"left by a crash").unwrap();
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    seams::arm("look-list");
    rt.keep_piece("~zod", &id, &kept, length, 1, piece(1)).unwrap();
    assert!(!seams::hit("look-list"), "inconclusive: the look never listed");
    assert!(left.exists(), "a look that failed removed something");
    rt.keep_piece("~zod", &id, &kept, length, 2, piece(2)).unwrap();
    assert!(left.exists(), "the directory was looked through twice in one life");
    assert!(rt.inner.dir_record("zod", &kept).unwrap().looked);
    drop(rt);
    // The next life's first keep there does the look.
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    rt.keep_piece("~zod", &id, &kept, length, 3, piece(3)).unwrap();
    assert!(!left.exists(), "the first keep of a life did not look");
    assert!(place.join(&named).exists());
    consistent(&rt, "~zod");
}

/// A look that fails does not let a later keep into the same directory look again: a copy held
/// at its sync while another keep goes into the directory is still there, is named when let go,
/// reads back whole, and the file's save finishes with every piece readable. A copy whose
/// commit's outcome is unknown is still on disk after later keeps there. (R14, H1, H6)
#[test]
fn a_directory_is_looked_through_once_whatever_comes_of_it() {
    let t = two("look-once");
    let data = contents(3 * CHUNK as usize, 7);
    let id = open_file(&t, &data, "");
    let length = data.len() as u64;
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(files::leaf).collect();
    let piece = |n: usize| data[n * CHUNK as usize..(n + 1) * CHUNK as usize].to_vec();
    let dir = t.b.begin_keeping("nec", &id, length, "", &leaves, Some("counter")).unwrap();
    let place = b_files(&t).join(hex(&dir));
    // The first keep of this life into the directory: its look fails, and its copy is then held
    // at its sync.
    let (reached, go) = seams::SyncGate::new(place.clone(), 1);
    let first = std::thread::spawn({
        let (rt, piece) = (t.b.clone(), piece(0));
        move || {
            seams::arm("look-list");
            let kept = rt.keep_piece("nec", &id, &dir, length, 0, piece);
            (kept.is_ok(), !seams::hit("look-list"))
        }
    });
    reached.recv_timeout(Duration::from_secs(30)).expect("inconclusive: the first copy never reached its sync");
    assert_eq!(on_disk(&b_files(&t))[&hex(&dir)].len(), 1, "inconclusive: the first copy is not on disk");
    // Another keep into the same directory, meanwhile: no second look.
    t.b.keep_piece("nec", &id, &dir, length, 1, piece(1)).unwrap();
    assert_eq!(on_disk(&b_files(&t))[&hex(&dir)].len(), 2, "a second look removed a copy on its way");
    go.send(()).unwrap();
    assert_eq!(first.join().unwrap(), (true, true), "the first keep failed, or its look never ran");
    consistent(&t.b, "nec");
    // A commit of unknown outcome: its copy is still on disk after later keeps there.
    let (_, pieces) = kept_of(&t.b, "nec", &id).unwrap();
    assert!(pieces[0].is_some() && pieces[1].is_some());
    let before = on_disk(&b_files(&t))[&hex(&dir)].clone();
    seams::arm("at-commit");
    assert!(t.b.keep_piece("nec", &id, &dir, length, 2, piece(2)).is_err());
    let stray: Vec<String> = on_disk(&b_files(&t))[&hex(&dir)].difference(&before).cloned().collect();
    assert_eq!(stray.len(), 1);
    t.b.keep_piece("nec", &id, &dir, length, 2, piece(2)).unwrap();
    assert!(place.join(&stray[0]).exists(), "a copy of unknown outcome was removed by a later keep");
    // The save finishes, and every piece of the file reads back.
    assert!(t.b.save_file("nec", "counter", "zod", "counter", &id).unwrap().done);
    let back: Vec<u8> = (0..3).flat_map(|n| t.b.file_chunk("nec", "counter", &id, n).unwrap()).collect();
    assert!(back == data);
    consistent(&t.b, "nec");
}

/// At most two copies no row may name in one kept directory in a runtime's life: past that,
/// nothing more is kept into it (an open passes the piece through; a save call says to try
/// later). A file being saved with strays is thrown away when its last save stops, not
/// returned to the cache. (R2, H5)
#[test]
fn strays_are_capped_at_two_per_kept_directory() {
    let t = two("strays");
    let data = contents(3 * CHUNK as usize, 2);
    let id = open_file(&t, &data, "");
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(files::leaf).collect();
    let dir = t.b.begin_keeping("nec", &id, data.len() as u64, "", &leaves, Some("counter")).unwrap();
    for n in 0..2u64 {
        seams::arm("at-commit");
        let piece = data[(n * CHUNK) as usize..((n + 1) * CHUNK) as usize].to_vec();
        assert!(t.b.keep_piece("nec", &id, &dir, data.len() as u64, n, piece).is_err());
        assert!(kept_of(&t.b, "nec", &id).unwrap().0.saving, "a file being saved was thrown away for a stray");
    }
    assert_eq!(strays(&t.b, "nec", &dir), 2);
    assert_eq!(on_disk(&b_files(&t))[&hex(&dir)].len(), 2);
    let third = data[2 * CHUNK as usize..].to_vec();
    assert!(matches!(t.b.keep_piece("nec", &id, &dir, data.len() as u64, 2, third), Err(Error::File(FileError::Unsettled))));
    assert_eq!(on_disk(&b_files(&t))[&hex(&dir)].len(), 2, "a copy was made past the cap");
    // A save call says to try later; an open passes pieces through.
    let refused = save(&t, "counter", &id);
    assert_eq!(refused.status, 503, "{}", refused.text());
    let whole = t.get(&t.path("counter", &id, "/content"), &[]);
    assert!(whole.status == 200 && whole.body == data);
    // Its last save stopped: thrown away, its strays forgotten.
    t.b.save_stop("~nec", "counter", &id).unwrap();
    assert!(kept_of(&t.b, "nec", &id).is_none());
    assert!(!b_files(&t).join(hex(&dir)).exists());
    assert_eq!(strays(&t.b, "nec", &dir), 0);
    consistent(&t.b, "nec");
}

/// The device has its piece before the ship keeps it: with the keep held at its sync, the
/// answer of one chunk and the whole of a one-chunk file are both had, and on a server whose
/// share for waiting on other ships is one place, another request that needs ~zod is answered
/// meanwhile: the held keep gave its places back. At most `MOST_KEEPING_AFTER` keeps after an
/// answer at once; with none free the piece is not kept. (R3, H7)
#[test]
fn the_device_has_its_piece_before_it_is_kept() {
    let t = two("piece-first");
    // Eight workers: four may download, and one of those may wait on another ship.
    let server = Server::start(t.b.clone(), ServerConfig { workers: 8, ..ServerConfig::default() }).unwrap();
    let get = |path: &str| http(&server, path, &[("Authorization", t.auth.as_str())]);
    let (one, two) = (open_file(&t, &contents(CHUNK as usize, 1), ""), open_file(&t, &contents(500, 2), ""));
    let others = [open_file(&t, &contents(700, 3), ""), open_file(&t, &contents(800, 4), "")];
    for ((id, rest, expected), other) in [(one, "/chunks/0", contents(CHUNK as usize, 1)), (two, "/content", contents(500, 2))].into_iter().zip(others) {
        let (reached, go) = seams::SyncGate::new(b_files(&t), 1);
        let answer = get(&t.path("counter", &id, rest));
        assert!(answer.status == 200 && answer.body == expected, "{rest}");
        reached.recv_timeout(Duration::from_secs(30)).expect("inconclusive: the keep never reached its sync");
        // The keep is held: the piece is not kept yet, and a request that needs ~zod is answered.
        assert_eq!(kept_of(&t.b, "nec", &id).unwrap().1, vec![None], "{rest}");
        let meanwhile = get(&t.path("counter", &other, ""));
        assert_eq!(meanwhile.status, 200, "{rest}: {}", meanwhile.text());
        go.send(()).unwrap();
        held_soon(&t.b, "nec", &id, Some(0));
    }
    // Both places for keeping after an answer taken: a piece is passed on and not kept.
    let three = open_file(&t, &contents(900, 5), "");
    let (first, second) = (t.b.keeping_after().unwrap(), t.b.keeping_after().unwrap());
    assert!(t.b.keeping_after().is_none());
    let mut opened = t.b.open_remote("nec", "zod", "counter", &three).unwrap();
    let (piece, fetched) = opened.piece(0).unwrap();
    assert!(fetched && piece == contents(900, 5));
    assert!(matches!(opened.keep_after(0, piece), Err(Error::File(FileError::Unsettled))));
    assert_eq!(kept_of(&t.b, "nec", &three).unwrap().1, vec![None]);
    drop((first, second));
}

/// How long one keep of a whole 1 MiB piece takes: 50 of them, on this machine, with every
/// commit synced as the default durability has it. Printed, for the report; asserted only to
/// be under a generous bound. (R3)
#[test]
fn how_long_one_keep_takes() {
    let dir = TempDir::new("keep-time");
    let rt = lone(&dir, Config::default());
    let mut took = Vec::new();
    for seed in 0..50u8 {
        let piece = contents(CHUNK as usize, seed);
        let id = files::id_of(&piece);
        let kept = rt.begin_keeping("~zod", &id, CHUNK, "", &[files::leaf(&piece)], None).unwrap();
        let started = Instant::now();
        rt.keep_piece("~zod", &id, &kept, CHUNK, 0, piece).unwrap();
        took.push(started.elapsed());
    }
    took.sort();
    eprintln!("one keep of 1 MiB: median {:?}, worst {:?}, of {}", took[took.len() / 2], took[took.len() - 1], took.len());
    assert!(took[took.len() - 1] < Duration::from_secs(10));
}

/// A held file opens with no place for waiting on another ship: with other ships' share taken
/// by stalled requests, and on a server with two workers, what a held file is and its chunks
/// are had; on two workers its whole contents are refused as a file of the ship's own would be.
/// (R4, H7)
#[test]
fn a_held_file_opens_with_no_place_for_waiting_on_another_ship() {
    // Deadlines longer than the watchdogs below, so the stalled requests hold their places until
    // the barrier goes.
    let t = two_with("no-share", (fast(), held_net()), (fast(), held_net()), &["~nec"]);
    let data = contents(2 * CHUNK as usize + 3, 4);
    let held = open_file(&t, &data, "");
    assert!(t.get(&t.path("counter", &held, "/content"), &[]).body == data);
    held_soon(&t.b, "nec", &held, None);
    let (slow_one, slow_two, unkept) = (open_file(&t, &contents(10, 5), ""), open_file(&t, &contents(11, 6), ""), open_file(&t, &contents(12, 7), ""));
    // The stalled requests are held at ~zod by a barrier the test lets go after its assertions;
    // their first question counted, once a request.
    let waiting = Arc::new(AtomicUsize::new(0));
    let count = waiting.clone();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let holding = gate.clone();
    t.lie(move |asked, _| {
        if matches!(asked, peer_request::Body::FileAbout(_)) {
            count.fetch_add(1, Ordering::SeqCst);
        }
        Some(Lie::Held(holding.clone()))
    });
    std::thread::scope(|scope| {
        let stalled: Vec<_> = [slow_one, slow_two].into_iter().map(|id| scope.spawn({
            let t = &t;
            move || t.get(&t.path("counter", &id, ""), &[]).status
        })).collect();
        let until = Instant::now() + Duration::from_secs(20);
        while waiting.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < until, "inconclusive: the stalled requests never asked ~zod");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Other ships' share is taken: a file that needs ~zod is told to try again ...
        let busy = t.get(&t.path("counter", &unkept, ""), &[]);
        assert_eq!((busy.status, busy.header("Retry-After")), (503, Some("1")));
        // ... and the held one is had whole, in part and by chunk.
        assert_eq!(t.get(&t.path("counter", &held, ""), &[]).status, 200);
        assert!(t.get(&t.path("counter", &held, "/chunks/1"), &[]).body == data[CHUNK as usize..2 * CHUNK as usize]);
        assert!(t.get(&t.path("counter", &held, "/content"), &[]).body == data);
        gate.close();
        for status in stalled {
            assert_eq!(status.join().unwrap(), 200);
        }
    });
    t.honest();
    // Two workers: no download places, and no waiting on another ship at all.
    let small = Server::start(t.b.clone(), ServerConfig { workers: 2, ..ServerConfig::default() }).unwrap();
    let auth = ("Authorization", t.auth.as_str());
    assert_eq!(http(&small, &t.path("counter", &held, ""), &[auth]).status, 200);
    assert!(http(&small, &t.path("counter", &held, "/chunks/0"), &[auth]).body == data[..CHUNK as usize]);
    // Whole contents take a download place, as a file of the ship's own does: none here.
    assert_eq!(http(&small, &t.path("counter", &held, "/content"), &[auth]).status, 503);
    let own = put(&t.b, "~nec", "counter", &contents(20, 8), "");
    assert_eq!(http(&small, &format!("/ships/nec/agents/counter/files/{}/content", hex(&own)), &[auth]).status, 503);
    assert_eq!(http(&small, &format!("/ships/nec/agents/counter/files/{}/chunks/0", hex(&own)), &[auth]).status, 200);
    // A file not held cannot be waited for on two workers.
    let none = http(&small, &t.path("counter", &unkept, ""), &[auth]);
    assert_eq!((none.status, none.header("Retry-After")), (503, None));
}

/// Making room drains the trash even when nothing new is thrown away: a removal that failed
/// once is tried again at the next piece that finds no room. (R5)
#[test]
fn the_trash_is_drained_when_a_piece_finds_no_room() {
    let dir = TempDir::new("drain-on-room");
    let rt = lone(&dir, Config { max_cache_bytes: CHUNK, ..fast() });
    keep_lone(&rt, "~zod", &contents(CHUNK as usize, 1));
    let piece = contents(CHUNK as usize, 2);
    let id = files::id_of(&piece);
    let kept = rt.begin_keeping("~zod", &id, CHUNK, "", &[files::leaf(&piece)], None).unwrap();
    // The first goes to make room; removing its bytes fails; the piece does not fit.
    seams::arm("remove");
    assert!(matches!(rt.keep_piece("~zod", &id, &kept, CHUNK, 0, piece.clone()), Err(Error::File(FileError::NoRoom))));
    assert_eq!(rt.cache_bytes("~zod").unwrap(), (0, CHUNK, 0));
    // Storage works again: the next try throws nothing new away, drains, and fits.
    rt.keep_piece("~zod", &id, &kept, CHUNK, 0, piece).unwrap();
    assert_eq!(rt.cache_bytes("~zod").unwrap(), (CHUNK, 0, 0));
    consistent(&rt, "~zod");
}

/// One request throws away no more than one budget: 64 saves of large files gone stale with
/// keeping off are stopped, and their files thrown away, a budget's worth at a time. (R6, H5)
#[test]
fn one_request_throws_away_no_more_than_its_budget() {
    let dir = TempDir::new("budget");
    let rt = lone(&dir, Config { max_cache_bytes: 0, max_file_bytes: 1 << 40, ..fast() });
    let chunks = 2048u64;
    let length = chunks * CHUNK;
    for seed in 0..64u32 {
        let leaves: Vec<[u8; 32]> = (0..chunks as u32).map(|n| files::leaf(&[n.to_le_bytes(), seed.to_le_bytes()].concat())).collect();
        let id = files::file_id(length, &files::root(&leaves));
        rt.begin_keeping("~zod", &id, length, "", &leaves, Some("counter")).unwrap();
    }
    sql(&rt, "~zod", "UPDATE saves SET touched = 1", params![]);
    // A budget's worth: as many files of 2,049 rows as fit 65,538 rows.
    let each = (crate::kept::THROW_ROWS / (chunks + 1)) as usize;
    let mut left = 64usize;
    while left > 0 {
        let (upload, _) = rt.upload_start("~zod", "counter", 5, "").unwrap();
        rt.upload_abandon("~zod", "counter", &upload).unwrap();
        let now = kept_count(&rt, "~zod");
        assert_eq!(now, left.saturating_sub(each), "one request threw away {} files", left - now);
        left = now;
    }
}

/// Clearing everything clears whatever `max_kept` now is, in pages; and the sweep brings the
/// count down to it. (R7, H8)
#[test]
fn clearing_everything_clears_whatever_max_kept_now_is() {
    let dir = TempDir::new("clear-lowered");
    let rt = lone(&dir, fast());
    let many = crate::kept::MAX_KEPT_LISTED + 44;
    for n in 0..many {
        let data = [(n % 256) as u8, (n / 256) as u8, 9];
        rt.begin_keeping("~zod", &files::id_of(&data), 3, "", &[files::leaf(&data)], None).unwrap();
    }
    drop(rt);
    let rt = Runtime::open(&dir.0, Config { max_kept: 1, ..fast() }).unwrap();
    assert_eq!(rt.kept_clear_all("~zod").unwrap(), Cleared { thrown_away: many as u64, being_saved: 0 });
    assert!(rt.kept("~zod", None, 10).unwrap().is_empty());
    drop(rt);
    // And the sweep: four kept, then the setting lowered to one.
    let dir = TempDir::new("sweep-lowered");
    let rt = lone(&dir, fast());
    let ids: Vec<[u8; 32]> = (0..4u8).map(|n| keep_lone(&rt, "~zod", &[n, 1]).0).collect();
    for (n, id) in ids.iter().enumerate() {
        sql(&rt, "~zod", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&id[..], (store::now_ms() - 10_000 + n as u64 * 1_000) as i64]);
    }
    drop(rt);
    let rt = Runtime::open(&dir.0, Config { max_kept: 1, ..fast() }).unwrap();
    rt.upload_start("~zod", "counter", 5, "").unwrap();
    assert_eq!(kept_count(&rt, "~zod"), 1);
    assert!(kept_of(&rt, "~zod", &ids[3]).is_some(), "not the newest was left");
}

/// A save begun between clearing's listing and its batch is left alone, and counted. (R8, H8)
#[test]
fn a_save_begun_during_a_clear_is_left_alone_and_counted() {
    let dir = TempDir::new("clear-race");
    let rt = lone(&dir, fast());
    let (x, _) = keep_lone(&rt, "~zod", &contents(10, 1));
    let (y, _) = keep_lone(&rt, "~zod", &contents(10, 2));
    let saver = rt.clone();
    seams::on_before_batch(move || sql(&saver, "~zod", "INSERT INTO saves VALUES (?1, 'counter', ?2)", params![&x[..], store::now_ms() as i64]));
    assert_eq!(rt.kept_clear_all("~zod").unwrap(), Cleared { thrown_away: 1, being_saved: 1 });
    assert!(kept_of(&rt, "~zod", &x).unwrap().0.saving);
    assert!(kept_of(&rt, "~zod", &y).is_none());
}

/// A piece given up between a save's last look and its finish makes the finish refuse; no file
/// is made, and the next call fetches it and finishes. (R12, H1)
#[test]
fn a_piece_given_up_before_the_finish_stops_the_finish() {
    let t = two("before-finish");
    let data = contents(2 * CHUNK as usize, 9);
    let id = open_file(&t, &data, "");
    assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    held_soon(&t.b, "nec", &id, None);
    let (kept, pieces) = kept_of(&t.b, "nec", &id).unwrap();
    let copy = b_files(&t).join(hex(&kept.dir)).join(format!("0.{}", hex(&pieces[0].unwrap())));
    let rt = t.b.clone();
    seams::on_before_finish(move || {
        let mut bad = fs::read(&copy).unwrap();
        bad[40] ^= 1;
        fs::write(&copy, bad).unwrap();
        // Read back, found bad, and given up.
        let mut opened = rt.open_remote("nec", "zod", "counter", &id).unwrap();
        assert!(opened.piece(0).unwrap().1, "inconclusive: the bad copy was read as held");
    });
    assert!(matches!(t.b.save_file("nec", "counter", "zod", "counter", &id), Err(crate::kept::SaveFailed::Here(Error::File(FileError::Incomplete)))));
    assert!(t.b.inner.with_ship("nec", |held| Ok(store::file_by_id(&lock(&held.conn), &id)?)).unwrap().is_none());
    assert_eq!(kept_of(&t.b, "nec", &id).unwrap().1[0], None);
    assert!(t.b.save_file("nec", "counter", "zod", "counter", &id).unwrap().done);
    assert!(t.b.file_chunk("nec", "counter", &id, 0).unwrap() == data[..CHUNK as usize]);
    consistent(&t.b, "nec");
}

/// A file being saved, a held copy found bad, its removal failing, and the ship then over its
/// allowance: no piece is taken for the file while it is over, and once the removal is done
/// the piece is kept. (R12, H5)
#[test]
fn a_saving_file_takes_no_piece_while_the_ship_is_over_its_allowance() {
    let cfg = Config { max_file_bytes: 2 * CHUNK, save_slice_millis: 0, ..fast() };
    let t = two_with("over", (fast(), NetConfig::default()), (cfg, NetConfig::default()), &["~nec"]);
    let data = contents(2 * CHUNK as usize, 10);
    let id = open_file(&t, &data, "");
    assert_eq!(save_reply(&save(&t, "counter", &id)), (false, 0, 2));
    assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    held_soon(&t.b, "nec", &id, None);
    let (kept, pieces) = kept_of(&t.b, "nec", &id).unwrap();
    let copy = b_files(&t).join(hex(&kept.dir)).join(format!("0.{}", hex(&pieces[0].unwrap())));
    let mut bad = fs::read(&copy).unwrap();
    bad[40] ^= 1;
    fs::write(&copy, bad).unwrap();
    // Given up, and its removal fails: held and reserved are within, to be removed is not.
    seams::arm("remove");
    let mut opened = t.b.open_remote("nec", "zod", "counter", &id).unwrap();
    let (piece, fetched) = opened.piece(0).unwrap();
    assert!(fetched);
    assert_eq!(t.b.files_to_remove("nec").unwrap(), (CHUNK, 1), "inconclusive: the bad copy was removed");
    assert!(matches!(opened.keep(0, piece.clone()), Err(Error::File(FileError::NoRoom))));
    assert_eq!(kept_of(&t.b, "nec", &id).unwrap().1[0], None);
    // The next file operation removes it; then the piece is taken.
    assert!(matches!(t.b.upload_start("~nec", "counter", 5, ""), Err(Error::File(FileError::NoRoom))));
    assert_eq!(t.b.files_to_remove("nec").unwrap(), (0, 0));
    opened.keep(0, piece).unwrap();
    consistent(&t.b, "nec");
}

/// With keeping on, a ship that lies is caught before anything wrong is passed on, and nothing
/// it says is kept: every lie of part 2's matrix that applies, each on a file not kept yet.
/// (R12, H1)
#[test]
fn a_lying_ship_is_caught_and_nothing_it_says_is_kept() {
    let t = two("liar-matrix");
    let data = contents(3 * CHUNK as usize + 5, 6);
    let id = open_file(&t, &data, "");
    let info = || t.get(&t.path("counter", &id, ""), &[]);
    let content = || t.get(&t.path("counter", &id, "/content"), &[]);
    let chunk = |n: u64| t.get(&t.path("counter", &id, &format!("/chunks/{n}")), &[]);
    let fresh = || {
        t.b.kept_clear_all("nec").unwrap();
        assert!(kept_of(&t.b, "nec", &id).is_none());
    };
    let changed = |change: fn(&mut PeerReply)| {
        move |_: &peer_request::Body, honest: &PeerReply| {
            let mut reply = honest.clone();
            change(&mut reply);
            Some(Lie::Reply(reply))
        }
    };
    let chunk_lies: [(&str, fn(&mut Vec<u8>)); 3] = [
        ("wrong bytes", |data| data[7] ^= 1),
        ("short", |data| {
            data.pop();
        }),
        ("long", |data| data.push(0)),
    ];
    for (what, change) in chunk_lies {
        fresh();
        t.lie(move |asked, honest| {
            let mut reply = honest.clone();
            match (asked, &mut reply.body) {
                (peer_request::Body::FileChunk(FileWanted { index: 1, .. }), Some(peer_reply::Body::FileChunk(sent))) => change(&mut sent.data),
                _ => return None,
            }
            Some(Lie::Reply(reply))
        });
        assert_eq!(chunk(1).status, 502, "{what}");
        let whole = content();
        assert!(whole.status == 200 && whole.body == data[..CHUNK as usize], "{what}: {} bytes passed on", whole.body.len());
        assert_eq!(kept_of(&t.b, "nec", &id).expect("kept once checked").1[1], None, "{what}: a lie was kept");
        consistent(&t.b, "nec");
    }
    let lies: [(&str, fn(&mut PeerReply)); 8] = [
        ("length nought", |reply| {
            if let Some(peer_reply::Body::FileAbout(facts)) = &mut reply.body {
                facts.length = 0;
            }
        }),
        ("length", |reply| {
            if let Some(peer_reply::Body::FileAbout(facts)) = &mut reply.body {
                facts.length += 1;
            }
        }),
        ("length short", |reply| {
            if let Some(peer_reply::Body::FileAbout(facts)) = &mut reply.body {
                facts.length -= 1;
            }
        }),
        ("a hash", |reply| {
            if let Some(peer_reply::Body::FileLeaves(sent)) = &mut reply.body {
                sent.hashes[40] ^= 1;
            }
        }),
        ("a hash too few", |reply| {
            if let Some(peer_reply::Body::FileLeaves(sent)) = &mut reply.body {
                sent.hashes.truncate(sent.hashes.len() - 32);
            }
        }),
        ("a hash too many", |reply| {
            if let Some(peer_reply::Body::FileLeaves(sent)) = &mut reply.body {
                sent.hashes.extend_from_slice(&[9; 32]);
            }
        }),
        ("hashes not whole", |reply| {
            if let Some(peer_reply::Body::FileLeaves(sent)) = &mut reply.body {
                sent.hashes.push(1);
            }
        }),
        ("hashes in place of what the file is", |reply| {
            if matches!(reply.body, Some(peer_reply::Body::FileAbout(_))) {
                reply.body = Some(peer_reply::Body::FileLeaves(FileHashes::default()));
            }
        }),
    ];
    for (what, change) in lies {
        fresh();
        t.lie(changed(change));
        for (route, answer) in [("info", info()), ("content", content()), ("chunk", chunk(0))] {
            assert_eq!(answer.status, 502, "{what}, {route}: {}", answer.text());
            kept_from_acting(&answer);
        }
        assert!(kept_of(&t.b, "nec", &id).is_none(), "{what}: a file was kept on what a liar said");
    }
    // A reply of another kind, a refusal, and words of refusal: nothing kept.
    fresh();
    t.lie(|_, _| Some(Lie::Reply(PeerReply { body: Some(peer_reply::Body::Pong(Pong::default())), refused: String::new() })));
    assert_eq!(info().status, 502);
    t.lie(|_, _| Some(Lie::Reply(PeerReply { body: None, refused: "no".into() })));
    assert_eq!(info().status, 502);
    t.lie(|_, _| Some(Lie::Reply(PeerReply { body: Some(peer_reply::Body::FileAbout(FileFacts { denied: "no".into(), ..FileFacts::default() })), refused: String::new() })));
    assert_eq!(info().status, 404);
    assert!(kept_of(&t.b, "nec", &id).is_none());
    // A chunk answered with something else, or refused, or cut off part way: never kept.
    t.lie(|asked, _| match asked {
        peer_request::Body::FileChunk(FileWanted { index: 0, .. }) => Some(Lie::Reply(PeerReply { body: Some(peer_reply::Body::FileAbout(FileFacts::default())), refused: String::new() })),
        peer_request::Body::FileChunk(FileWanted { index: 1, .. }) => Some(Lie::Reply(PeerReply { body: Some(peer_reply::Body::FileChunk(FileBytes { denied: "no".into(), data: Vec::new() })), refused: String::new() })),
        peer_request::Body::FileChunk(FileWanted { index: 2.., .. }) => Some(Lie::Cut),
        _ => None,
    });
    assert_eq!(chunk(0).status, 502);
    assert_eq!(chunk(1).status, 404);
    assert!(matches!(chunk(2).status, 502 | 504));
    assert!(content().body.is_empty());
    assert_eq!(kept_of(&t.b, "nec", &id).expect("kept once checked").1, vec![None; 4]);
    consistent(&t.b, "nec");
    t.honest();
    assert!(content().body == data);
    held_soon(&t.b, "nec", &id, None);
    consistent(&t.b, "nec");
}

/// With keeping on, fetching writes nothing on the ship asked: no file, no directory, no row.
/// (R12, H9)
#[test]
fn with_keeping_on_nothing_is_written_on_the_ship_asked() {
    let t = two("nothing-on-a");
    let data = contents(2 * CHUNK as usize + 5, 2);
    let id = open_file(&t, &data, "");
    // Once, so that both ships are awake and connected.
    assert_eq!(t.get(&t.path("counter", &[1; 32], ""), &[]).status, 404);
    let (files_before, rows_before) = (super::listing(&t._dirs.0 .0), super::rows(&t.a, "~zod"));
    assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    assert_eq!(t.get(&t.path("counter", &id, "/chunks/1"), &[]).status, 200);
    held_soon(&t.b, "nec", &id, None);
    assert_eq!((super::listing(&t._dirs.0 .0), super::rows(&t.a, "~zod")), (files_before, rows_before));
}

/// A save that stops goes back to the cache only if its rows fit the cache's allowance of rows
/// too; if not, it is thrown away. (R1, H5)
#[test]
fn a_stopped_save_goes_back_to_the_cache_only_if_its_rows_fit() {
    // 64 MiB of ship file: 4 MiB for the cache's rows; files of 8,192 chunks take 1 MiB and 1 KiB.
    let dir = TempDir::new("stop-rows");
    let rt = lone(&dir, Config { max_ship_bytes: 64 << 20, ..fast() });
    let length = 8192 * CHUNK;
    let wide = |seed: u8| {
        let leaves: Vec<[u8; 32]> = (0..8192u32).map(|n| files::leaf(&[&n.to_le_bytes()[..], &[seed]].concat())).collect();
        (files::file_id(length, &files::root(&leaves)), leaves)
    };
    for seed in 0..3u8 {
        let (id, leaves) = wide(seed);
        rt.begin_keeping("~zod", &id, length, "", &leaves, None).unwrap();
    }
    let (saving, leaves) = wide(9);
    rt.begin_keeping("~zod", &saving, length, "", &leaves, Some("counter")).unwrap();
    assert_eq!(kept_count(&rt, "~zod"), 4);
    // Back in the cache it would make four such files' rows, over 4 MiB: thrown away instead.
    rt.save_stop("~zod", "counter", &saving).unwrap();
    assert!(kept_of(&rt, "~zod", &saving).is_none(), "a stopped save went back to the cache over its allowance of rows");
    assert!(rt.cache_rows("~zod").unwrap() <= (64 << 20) / 16);
    assert_eq!(kept_count(&rt, "~zod"), 3);
}

/// A cached file with a stray that the request which made the stray could not throw away goes
/// at the sweep. (R2, H6)
#[test]
fn the_sweep_throws_away_a_cached_file_left_with_a_stray() {
    let dir = TempDir::new("stray-sweep");
    let rt = lone(&dir, fast());
    let piece = contents(500, 1);
    let id = files::id_of(&piece);
    let kept = rt.begin_keeping("~zod", &id, 500, "", &[files::leaf(&piece)], None).unwrap();
    // The keep's commit has an unknown outcome (a stray), and so does the throwing away that
    // follows it: the file is still there, with a stray.
    seams::arm("at-commit");
    seams::arm("at-commit");
    assert!(rt.keep_piece("~zod", &id, &kept, 500, 0, piece).is_err());
    assert!(!seams::hit("at-commit"), "inconclusive: the throwing away was never tried");
    assert!(kept_of(&rt, "~zod", &id).is_some());
    assert_eq!(strays(&rt, "zod", &kept), 1);
    let (upload, _) = rt.upload_start("~zod", "counter", 5, "").unwrap();
    rt.upload_abandon("~zod", "counter", &upload).unwrap();
    assert!(kept_of(&rt, "~zod", &id).is_none(), "the sweep left a cached file with a stray");
    assert_eq!(strays(&rt, "zod", &kept), 0);
}

/// Copies on their way count against the cap with strays: three keeps into one saving
/// directory overlapping, the first two held at their sync, and the third is refused with no
/// copy made; after both of the first two end in an unknown commit the strays are two, not
/// three. (R15, H5)
#[test]
fn copies_on_their_way_count_against_the_cap_with_strays() {
    let dir_root = TempDir::new("on-their-way");
    let rt = lone(&dir_root, fast());
    let data = contents(3 * CHUNK as usize, 1);
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(files::leaf).collect();
    let (id, length) = (files::id_of(&data), data.len() as u64);
    let piece = |n: usize| data[n * CHUNK as usize..(n + 1) * CHUNK as usize].to_vec();
    let dir = rt.begin_keeping("~zod", &id, length, "", &leaves, Some("counter")).unwrap();
    let (reached, go) = seams::SyncGate::new(dir_root.0.join("files/zod").join(hex(&dir)), 2);
    let held: Vec<_> = (0..2)
        .map(|n| {
            let (rt, piece) = (rt.clone(), piece(n));
            std::thread::spawn(move || {
                seams::arm("at-commit");
                rt.keep_piece("~zod", &id, &dir, length, n as u64, piece).is_err()
            })
        })
        .collect();
    for _ in 0..2 {
        reached.recv_timeout(Duration::from_secs(30)).expect("inconclusive: a copy never reached its sync");
    }
    assert_eq!(rt.inner.dir_record("zod", &dir).unwrap().on_way, 2);
    assert!(matches!(rt.keep_piece("~zod", &id, &dir, length, 2, piece(2)), Err(Error::File(FileError::Unsettled))));
    assert_eq!(on_disk(&dir_root.0.join("files/zod"))[&hex(&dir)].len(), 2, "a third copy was made");
    go.send(()).unwrap();
    go.send(()).unwrap();
    for keep in held {
        assert!(keep.join().unwrap(), "inconclusive: a held keep's commit was not of unknown outcome");
    }
    let record = rt.inner.dir_record("zod", &dir).unwrap();
    assert_eq!((record.strays, record.on_way), (2, 0));
}

/// A kept directory cleared while a copy is on its way: the copy's commit is refused and its
/// removal fails, and no record is left once it ends; a throwing away that lands but reports an
/// error leaves a record the next sweep drops. (R15, H5)
#[test]
fn a_retired_directory_leaves_no_record() {
    let root = TempDir::new("retired");
    let rt = lone(&root, fast());
    let piece = contents(CHUNK as usize, 1);
    let id = files::id_of(&piece);
    let dir = rt.begin_keeping("~zod", &id, CHUNK, "", &[files::leaf(&piece)], None).unwrap();
    let (reached, go) = seams::SyncGate::new(root.0.join("files/zod").join(hex(&dir)), 1);
    let on_way = std::thread::spawn({
        let (rt, piece) = (rt.clone(), piece.clone());
        move || {
            // Its own removal, after its commit is refused, fails.
            seams::arm("remove");
            rt.keep_piece("~zod", &id, &dir, CHUNK, 0, piece)
        }
    });
    reached.recv_timeout(Duration::from_secs(30)).expect("inconclusive: the copy never reached its sync");
    // Cleared, the directory's removal failing so that the copy can go on to its commit.
    seams::arm("remove");
    assert_eq!(rt.kept_clear("~zod", &id).unwrap(), Cleared { thrown_away: 1, being_saved: 0 });
    assert!(rt.inner.dir_record("zod", &dir).unwrap().retired, "a directory thrown away with a copy on its way was not retired");
    go.send(()).unwrap();
    assert!(matches!(on_way.join().unwrap(), Err(Error::File(FileError::NotFound))));
    assert!(rt.inner.dir_record("zod", &dir).is_none(), "a retired record outlived its last copy");
    // A throwing away that lands and reports an error: the record stays until the next sweep.
    let other = contents(500, 2);
    let (other_id, other_dir) = keep_lone(&rt, "~zod", &other);
    assert!(rt.inner.dir_record("zod", &other_dir).is_some());
    seams::arm("commit-then-fail");
    assert!(rt.kept_clear("~zod", &other_id).is_err());
    assert!(kept_of(&rt, "~zod", &other_id).is_none());
    assert!(rt.inner.dir_record("zod", &other_dir).is_some(), "inconclusive: the record went without a sweep");
    let (upload, _) = rt.upload_start("~zod", "counter", 5, "").unwrap();
    rt.upload_abandon("~zod", "counter", &upload).unwrap();
    assert!(rt.inner.dir_record("zod", &other_dir).is_none(), "the sweep left a record of a directory that is gone");
}

/// A cached file with no held bytes and one stray, thrown away with its directory's removal
/// failing: the cache counts 1 MiB for the stray until the removal works. (R15, H5)
#[test]
fn a_stray_is_counted_from_when_its_directory_is_thrown_away() {
    let root = TempDir::new("charged");
    let rt = lone(&root, fast());
    let piece = contents(500, 1);
    let id = files::id_of(&piece);
    let kept = rt.begin_keeping("~zod", &id, 500, "", &[files::leaf(&piece)], None).unwrap();
    // A stray, and the throwing away that follows it of unknown outcome, so the file is left.
    seams::arm("at-commit");
    seams::arm("at-commit");
    assert!(rt.keep_piece("~zod", &id, &kept, 500, 0, piece).is_err());
    assert_eq!((kept_of(&rt, "~zod", &id).unwrap().0.held, strays(&rt, "zod", &kept)), (0, 1));
    seams::arm("remove");
    rt.kept_clear("~zod", &id).unwrap();
    assert_eq!(rt.cache_bytes("~zod").unwrap(), (0, CHUNK, 0), "a stray was not counted when its directory was thrown away");
    let (upload, _) = rt.upload_start("~zod", "counter", 5, "").unwrap();
    rt.upload_abandon("~zod", "counter", &upload).unwrap();
    assert_eq!(rt.cache_bytes("~zod").unwrap(), (0, 0, 0));
    assert!(!root.0.join("files/zod").join(hex(&kept)).exists());
}

/// A copy refused at its commit whose removal fails is a stray: a cached file is thrown away for
/// it, and the copy is counted against the cache until its directory is gone. (R15, H5)
#[test]
fn a_refused_copy_that_cannot_be_removed_is_a_stray() {
    let root = TempDir::new("refused-stray");
    let rt = lone(&root, Config { max_cache_bytes: CHUNK + CHUNK / 2, ..fast() });
    let data = contents(2 * CHUNK as usize, 4);
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(files::leaf).collect();
    let (id, length) = (files::id_of(&data), data.len() as u64);
    let dir = rt.begin_keeping("~zod", &id, length, "", &leaves, None).unwrap();
    rt.keep_piece("~zod", &id, &dir, length, 0, data[..CHUNK as usize].to_vec()).unwrap();
    // The second piece finds no room (nothing else may go for it), and its copy's removal fails.
    let place = root.0.join("files/zod").join(hex(&dir));
    assert_eq!(on_disk(&root.0.join("files/zod"))[&hex(&dir)].len(), 1);
    seams::arm("remove");
    assert!(matches!(rt.keep_piece("~zod", &id, &dir, length, 1, data[CHUNK as usize..].to_vec()), Err(Error::File(FileError::NoRoom))));
    assert!(kept_of(&rt, "~zod", &id).is_none(), "a cached file left with a stray was kept");
    assert!(rt.inner.dir_record("zod", &dir).is_none());
    // Its directory, the stray in it, gone at the drain that followed.
    assert!(!place.exists());
    assert_eq!(rt.cache_bytes("~zod").unwrap(), (0, 0, 0));
}

/// A save request throws away no more than its budget, whatever it finds: 64 saves run out
/// with keeping off, and an identical file uploaded between the save's look and its finish; the
/// redundant kept copy is thrown away with the room kept back for it. (R16, H5)
#[test]
fn a_save_throws_away_no_more_than_its_budget_at_the_finish() {
    let root = TempDir::new("finish-budget");
    let rt = lone(&root, Config { max_cache_bytes: 0, max_file_bytes: 1 << 40, ..fast() });
    for seed in 0..64u8 {
        let data = [seed, 7, 7];
        rt.begin_keeping("~zod", &files::id_of(&data), 3, "", &[files::leaf(&data)], Some("counter")).unwrap();
    }
    let data = contents(2 * CHUNK as usize, 1);
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(files::leaf).collect();
    let (id, length) = (files::id_of(&data), data.len() as u64);
    let dir = rt.begin_keeping("~zod", &id, length, "", &leaves, Some("counter")).unwrap();
    for n in 0..2 {
        rt.keep_piece("~zod", &id, &dir, length, n as u64, data[n * CHUNK as usize..(n + 1) * CHUNK as usize].to_vec()).unwrap();
    }
    // The same bytes, uploaded, finished between the save's look and its finish.
    let (upload, _) = rt.upload_start("~zod", "keeper", length, "").unwrap();
    for n in 0..2 {
        rt.upload_chunk("~zod", "keeper", &upload, n as u64, data[n * CHUNK as usize..(n + 1) * CHUNK as usize].to_vec()).unwrap();
    }
    sql(&rt, "~zod", "UPDATE saves SET touched = 1 WHERE id != ?1", params![&id[..]]);
    let finisher = rt.clone();
    seams::on_before_finish(move || {
        finisher.upload_finish("~zod", "keeper", &upload, None).unwrap();
    });
    let before = kept_count(&rt, "~zod");
    assert_eq!(before, 65);
    assert!(rt.save_file("zod", "counter", "nec", "counter", &id).unwrap().done);
    let thrown = before - kept_count(&rt, "~zod");
    assert!(thrown as u64 <= THROW_FILES, "one request threw away {thrown} kept files");
    assert!(kept_of(&rt, "~zod", &id).is_none(), "the redundant kept copy was not thrown away");
    assert!(rt.file_chunk("~zod", "counter", &id, 1).unwrap() == data[CHUNK as usize..]);
}

/// While the rows of the cache are over a lowered allowance: a new file is not kept, a stopped
/// save is thrown away, and a piece of a file already in the cache is kept (it adds no rows).
/// (R17, H5)
#[test]
fn while_the_rows_are_over_nothing_new_is_admitted() {
    let root = TempDir::new("rows-over");
    // 64 MiB of ship file: 4 MiB for the cache's rows.
    let rt = lone(&root, Config { max_ship_bytes: 64 << 20, ..fast() });
    let length = 8192 * CHUNK;
    let real = contents(CHUNK as usize, 1);
    let wide = |seed: u8| {
        let mut leaves: Vec<[u8; 32]> = (0..8192u32).map(|n| files::leaf(&[&n.to_le_bytes()[..], &[seed]].concat())).collect();
        leaves[0] = files::leaf(&real);
        (files::file_id(length, &files::root(&leaves)), leaves)
    };
    // Sixty-four small files, the oldest, and then two of 8,192 chunks, newer.
    let mut small = Vec::new();
    for n in 0..64u8 {
        small.push(keep_lone(&rt, "~zod", &[n, 3]).0);
    }
    for (n, id) in small.iter().enumerate() {
        sql(&rt, "~zod", "UPDATE kept SET used = ?2 WHERE id = ?1", params![&id[..], (store::now_ms() - 100_000 + n as u64) as i64]);
    }
    let wides: Vec<([u8; 32], [u8; 16])> = (0..2u8)
        .map(|seed| {
            let (id, leaves) = wide(seed);
            (id, rt.begin_keeping("~zod", &id, length, "", &leaves, None).unwrap())
        })
        .collect();
    let (saving, leaves) = wide(9);
    rt.begin_keeping("~zod", &saving, length, "", &leaves, Some("counter")).unwrap();
    drop(rt);
    // Lowered: 2 MiB for the cache's rows, and two wide files take 2 MiB and 2 KiB alone.
    let rt = Runtime::open(&root.0, Config { max_ship_bytes: 32 << 20, ..fast() }).unwrap();
    let allowance = (32 << 20) / 16;
    assert!(rt.cache_rows("~zod").unwrap() > allowance);
    // A new file: the sweep first throws away a budget of the oldest, which leaves the cache
    // over, and the file is not kept.
    let new = [9u8, 9];
    assert!(matches!(rt.begin_keeping("~zod", &files::id_of(&new), 2, "", &[files::leaf(&new)], None), Err(Error::File(FileError::NoRoom))));
    assert!(rt.cache_rows("~zod").unwrap() > allowance, "inconclusive: the cache is within again");
    assert!(kept_of(&rt, "~zod", &files::id_of(&new)).is_none());
    // A stopped save is thrown away, not returned to the cache.
    rt.save_stop("~zod", "counter", &saving).unwrap();
    assert!(kept_of(&rt, "~zod", &saving).is_none());
    // A piece of a file already in the cache is kept.
    let (id, dir) = wides[1];
    rt.keep_piece("~zod", &id, &dir, length, 0, real).unwrap();
    assert!(kept_of(&rt, "~zod", &id).unwrap().1[0].is_some());
    // And sweeps bring it down, a budget at a time.
    for _ in 0..4 {
        if rt.cache_rows("~zod").unwrap() <= allowance {
            break;
        }
        let (upload, _) = rt.upload_start("~zod", "counter", 5, "").unwrap();
        rt.upload_abandon("~zod", "counter", &upload).unwrap();
    }
    assert!(rt.cache_rows("~zod").unwrap() <= allowance, "sweeps did not bring the cache's rows within the allowance");
    consistent(&rt, "~zod");
}

/// A save call that finds its file's rows certainly do not vouch for its id ends its own save in
/// that call: with no other agent saving, the file is thrown away, and the call made again saves
/// it whole; with two, each ends its own, and after the second the file is gone. (R18, H1)
#[test]
fn a_save_that_finds_damaged_rows_ends_itself() {
    let t = two("damaged-save");
    let data = contents(2 * CHUNK as usize, 3);
    let id = open_file(&t, &data, "");
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(files::leaf).collect();
    let length = data.len() as u64;
    let damage = |dir: &[u8; 16]| sql(&t.b, "nec", "UPDATE kept_chunks SET hash = ?2 WHERE dir = ?1 AND n = 1", params![&dir[..], &[7u8; 32][..]]);
    // One agent.
    let dir = t.b.begin_keeping("nec", &id, length, "", &leaves, Some("counter")).unwrap();
    damage(&dir);
    assert_eq!(save(&t, "counter", &id).status, 500);
    assert!(kept_of(&t.b, "nec", &id).is_none(), "a damaged file with no save left was kept");
    assert_eq!(save_reply(&save(&t, "counter", &id)), (true, 2, 2));
    assert!(t.b.file_chunk("nec", "counter", &id, 1).unwrap() == data[CHUNK as usize..]);
    t.b.file_delete("~nec", "counter", &id).unwrap();
    // Two agents.
    let dir = t.b.begin_keeping("nec", &id, length, "", &leaves, Some("counter")).unwrap();
    t.b.begin_keeping("nec", &id, length, "", &leaves, Some("keeper")).unwrap();
    damage(&dir);
    assert_eq!(save(&t, "counter", &id).status, 500);
    let (kept, _) = kept_of(&t.b, "nec", &id).expect("another agent is saving it");
    assert!(kept.saving);
    assert!(t.b.saves("~nec", "counter").unwrap().is_empty() && t.b.saves("~nec", "keeper").unwrap().len() == 1);
    assert_eq!(save(&t, "keeper", &id).status, 500);
    assert!(kept_of(&t.b, "nec", &id).is_none());
    assert_eq!(save_reply(&save(&t, "keeper", &id)), (true, 2, 2));
}

/// A sweep with no owner goes with its directory, not before it: a file made from a kept file
/// with one stray, the sweep of that stray failing, the last claim deleted and the directory's
/// removal failing: the stray's 1 MiB stays counted until the directory is gone, and then
/// nothing is counted or recorded. (R21, H5, H6)
#[test]
fn an_ownerless_sweep_goes_with_its_directory() {
    let root = TempDir::new("ownerless-sweep");
    let rt = lone(&root, fast());
    let data = contents(CHUNK as usize, 6);
    let id = files::id_of(&data);
    let dir = rt.begin_keeping("~zod", &id, CHUNK, "", &[files::leaf(&data)], Some("counter")).unwrap();
    // A stray (a commit of unknown outcome), then the piece kept.
    seams::arm("at-commit");
    assert!(rt.keep_piece("~zod", &id, &dir, CHUNK, 0, data.clone()).is_err());
    rt.keep_piece("~zod", &id, &dir, CHUNK, 0, data.clone()).unwrap();
    let place = root.0.join("files/zod").join(hex(&dir));
    assert_eq!(on_disk(&root.0.join("files/zod"))[&hex(&dir)].len(), 2);
    let counted = || rt.inner.with_ship("~zod", |held| Ok(store::counted_bytes(&lock(&held.conn))?)).unwrap();
    let recorded = || rt.inner.with_ship("~zod", |held| Ok(lock(&held.conn).query_row("SELECT COUNT(*) FROM file_trash", [], |r| r.get::<_, i64>(0))?)).unwrap();
    // Saved, the sweep of the stray failing: the file and the stray's 1 MiB counted.
    seams::arm("remove");
    assert!(rt.save_file("zod", "counter", "nec", "counter", &id).unwrap().done);
    assert_eq!((counted(), recorded()), (2 * CHUNK, 1));
    // The last claim deleted, the sweep failing again first, then the directory's removal.
    seams::arm("remove");
    seams::arm("remove");
    rt.file_delete("~zod", "counter", &id).unwrap();
    assert!(place.exists(), "inconclusive: the directory went");
    assert_eq!(on_disk(&root.0.join("files/zod"))[&hex(&dir)].len(), 2);
    assert_eq!(counted(), 2 * CHUNK, "the stray stopped being counted while it is on disk");
    // The directory goes at the next drain, and every record of it with it.
    rt.inner.empty_trash("zod");
    assert!(!place.exists());
    assert_eq!((counted(), recorded()), (0, 0));
}

/// What a save call's opening sweep throws away lands even when the file it asks for is then
/// refused: an older save run out (X, 1 MiB held, which cannot go back to a cache of 512 KiB),
/// a newer one (Y, 32 GiB, nothing held) the budget cannot take after X, and Z asked for with no
/// room for it while Y is reserved. The first call throws X away and is refused; the next settles
/// Y back into the cache and Z is saved. (R22, H5)
#[test]
fn a_sweep_lands_though_the_save_that_ran_it_is_refused() {
    let cfg = Config { max_file_bytes: (32 << 30) + CHUNK, max_cache_bytes: CHUNK / 2, ..fast() };
    let t = two_with("sweep-lands", (fast(), NetConfig::default()), (cfg, NetConfig::default()), &["~nec"]);
    let z_data = contents(2 * CHUNK as usize, 3);
    let z = open_file(&t, &z_data, "");
    let z_leaves: Vec<[u8; 32]> = z_data.chunks(CHUNK as usize).map(files::leaf).collect();
    t.b.begin_keeping("nec", &z, z_data.len() as u64, "", &z_leaves, None).unwrap();
    let x_data = contents(CHUNK as usize, 4);
    let x = files::id_of(&x_data);
    let x_dir = t.b.begin_keeping("nec", &x, CHUNK, "", &[files::leaf(&x_data)], Some("counter")).unwrap();
    t.b.keep_piece("nec", &x, &x_dir, CHUNK, 0, x_data).unwrap();
    let y_length = files::FANOUT as u64 * CHUNK;
    let y_leaves: Vec<[u8; 32]> = (0..files::FANOUT as u32).map(|n| files::leaf(&n.to_le_bytes())).collect();
    let y = files::file_id(y_length, &files::root(&y_leaves));
    t.b.begin_keeping("nec", &y, y_length, "", &y_leaves, Some("counter")).unwrap();
    sql(&t.b, "nec", "UPDATE saves SET touched = 1 WHERE id = ?1", params![&x[..]]);
    sql(&t.b, "nec", "UPDATE saves SET touched = 2 WHERE id = ?1", params![&y[..]]);
    // The first call: X thrown away, Y left (the budget keeps room back for Z), Z refused.
    let first = save(&t, "counter", &z);
    assert_ne!(first.status, 200, "inconclusive: Z was admitted at once");
    assert!(kept_of(&t.b, "nec", &x).is_none(), "the expiry of X was rolled back with the refusal");
    assert!(kept_of(&t.b, "nec", &y).unwrap().0.saving);
    // The next: Y settled back into the cache, and Z saved.
    assert_eq!(save_reply(&save(&t, "counter", &z)), (true, 2, 2));
    assert!(!kept_of(&t.b, "nec", &y).unwrap().0.saving);
    assert!(t.b.file_chunk("nec", "counter", &z, 1).unwrap() == z_data[CHUNK as usize..]);
    consistent(&t.b, "nec");
}

/// A file refused keeping (here for the count) still leaves a stale file in the cache thrown
/// away by the sweep that ran first. (R22, H5)
#[test]
fn a_refused_keep_leaves_the_sweep_done() {
    let root = TempDir::new("refused-keep");
    let rt = lone(&root, fast());
    let (stale, _) = keep_lone(&rt, "~zod", &[1, 2, 3]);
    for seed in 0..2u8 {
        let data = [seed, 9];
        rt.begin_keeping("~zod", &files::id_of(&data), 2, "", &[files::leaf(&data)], Some("counter")).unwrap();
    }
    sql(&rt, "~zod", "UPDATE kept SET used = 1 WHERE id = ?1", params![&stale[..]]);
    drop(rt);
    // Two kept at most: the two being saved fill that once the stale one has gone.
    let rt = Runtime::open(&root.0, Config { max_kept: 2, ..fast() }).unwrap();
    let new = [7u8, 7];
    assert!(matches!(rt.begin_keeping("~zod", &files::id_of(&new), 2, "", &[files::leaf(&new)], None), Err(Error::TooMany(_))));
    assert!(kept_of(&rt, "~zod", &stale).is_none(), "the stale file's throwing away was rolled back with the refusal");
    assert_eq!(kept_count(&rt, "~zod"), 2);
    consistent(&rt, "~zod");
}
