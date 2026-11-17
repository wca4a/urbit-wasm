//! Fetching a file from another ship, for this ship's owner's devices.
//!
//! The owner of a ship here names a file on another ship: that ship, the agent there that
//! claims the file, and the file's id. This ship asks the other for what the file is, then for
//! the hashes of its chunks, and then for each chunk wanted, one request at a time over the
//! ship-to-ship connection, and passes each chunk on. It keeps nothing: nothing is written to
//! disk or to the ship's file, and nothing learned in one HTTP request is used in another.
//!
//! The other ship is believed about nothing the id does not vouch for. The length it gives is
//! believed only once the hashes it sends, counted and hashed, come to exactly the id asked
//! for; and a chunk only once it is exactly as long as that length says and hashes to its
//! checked hash. Only the media type is taken on its word, and that goes through the same
//! check as a media type at upload (anything it refuses becomes `application/octet-stream`).
//! A lying, broken or replaced ship can make this fail, or stop short, and nothing else. No
//! text the other ship sends is ever passed on: a refusal is only a no.

use ship_proto::{peer_reply, peer_request, FileWanted, PeerRequest};

use crate::files::{self, chunk_count, chunk_len, group_count, group_hash, group_len, FANOUT};
use crate::net::{FileAskError, NetError, TOO_BUSY};
use crate::Runtime;

/// Why a file could not be had from another ship.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failed {
    /// The other ship said no. What it said is never passed on: only that it said no.
    Refused,
    /// What it sent fails a check, or is not what was asked for, or makes no sense.
    Wrong(&'static str),
    /// It could not be reached, or did not answer in time.
    Unreachable,
    /// This ship or the other has no room for the request just now; try again.
    Busy,
    /// No network is running here.
    NoNetwork,
    /// This runtime cannot carry a file's chunks: its messages are too small.
    Unfit,
}

/// A file on another ship, as far as it has been checked. Made by `Remote::open`, which checks
/// the length; then each chunk is fetched and checked on its own. Holds at most one list of
/// index hashes (1 MiB), one group of chunk hashes (1 MiB), and while a chunk is fetched, that
/// chunk.
pub(crate) struct Remote<A> {
    ask: A,
    length: u64,
    media_type: String,
    /// The index hash of every group, for a file of more than `FANOUT` chunks; checked against
    /// the id.
    groups: Option<Vec<[u8; 32]>>,
    /// The group of chunk hashes last fetched, and which it is; checked against the id, or
    /// against `groups`.
    group: Option<(u64, Vec<[u8; 32]>)>,
}

/// One question to the other ship and its answer: `Err` for anything but an answer.
pub(crate) type Ask<'a> = Box<dyn FnMut(peer_request::Body) -> Result<peer_reply::Body, Failed> + 'a>;

impl Runtime {
    /// Ask `to`, from `from` (a ship here), about the file `id` that `agent` there claims, as
    /// `Remote::open` does.
    pub(crate) fn remote_file<'a>(&'a self, from: &str, to: &str, agent: &str, id: &[u8; 32]) -> Result<Remote<Ask<'a>>, Failed> {
        let (from, to, agent, id) = (from.to_string(), to.to_string(), agent.to_string(), *id);
        let ask: Ask<'a> = Box::new(move |body: peer_request::Body| {
            let wanted = |index: u64| FileWanted { agent: agent.clone(), id: id.to_vec(), index };
            // The agent and the id are this request's own, whatever the caller put in.
            let body = match body {
                peer_request::Body::FileAbout(_) => peer_request::Body::FileAbout(wanted(0)),
                peer_request::Body::FileLeaves(asked) => peer_request::Body::FileLeaves(wanted(asked.index)),
                peer_request::Body::FileUpper(_) => peer_request::Body::FileUpper(wanted(0)),
                peer_request::Body::FileChunk(asked) => peer_request::Body::FileChunk(wanted(asked.index)),
                _ => return Err(Failed::Wrong("not a question about a file")),
            };
            match self.ask_for_file(&from, &to, PeerRequest { body: Some(body) }) {
                None => Err(Failed::NoNetwork),
                Some(Ok(reply)) => reply.body.ok_or(Failed::Wrong("a reply with nothing in it")),
                Some(Err(why)) => Err(failed(why)),
            }
        });
        Remote::open(ask, &id)
    }
}

/// What a failure to get an answer comes to.
fn failed(why: FileAskError) -> Failed {
    match why {
        FileAskError::Busy => Failed::Busy,
        FileAskError::Unfit => Failed::Unfit,
        FileAskError::Stopped => Failed::NoNetwork,
        FileAskError::Net(NetError::Refused(words)) if words == TOO_BUSY => Failed::Busy,
        // Refused for another reason: a chunk it could not read, a part it says is not there,
        // a request it does not know (an older runtime), messages too small at its end.
        FileAskError::Net(NetError::Refused(_)) => Failed::Wrong("the other ship would not answer that"),
        FileAskError::Net(NetError::Garbled) => Failed::Wrong("the other ship's answer made no sense"),
        FileAskError::Net(NetError::NotHere(_)) => Failed::Wrong("the asking ship is not here"),
        FileAskError::Net(NetError::Unlisted(_) | NetError::Unreachable(_) | NetError::TimedOut) => Failed::Unreachable,
    }
}

/// Hashes sent one after another, if they are exactly `count` of them.
fn hashes(bytes: &[u8], count: u64) -> Option<Vec<[u8; 32]>> {
    if bytes.len() % 32 != 0 || (bytes.len() / 32) as u64 != count {
        return None;
    }
    Some(bytes.chunks_exact(32).map(|hash| <[u8; 32]>::try_from(hash).expect("32 bytes")).collect())
}

fn wanted(index: u64) -> FileWanted {
    FileWanted { agent: String::new(), id: Vec::new(), index }
}

impl<A: FnMut(peer_request::Body) -> Result<peer_reply::Body, Failed>> Remote<A> {
    /// Ask what the file `id` is, and check it: the length, and the hashes that with it must
    /// come to `id`. Only once this returns is the length believed.
    pub(crate) fn open(mut ask: A, id: &[u8; 32]) -> Result<Remote<A>, Failed> {
        let peer_reply::Body::FileAbout(facts) = ask(peer_request::Body::FileAbout(wanted(0)))? else {
            return Err(Failed::Wrong("a reply of the wrong kind"));
        };
        if !facts.denied.is_empty() {
            return Err(Failed::Refused);
        }
        let length = facts.length;
        // Nothing is asked for, or made room for, on a length that could not be checked in
        // two levels: whatever it is, it is not believed.
        if !files::fetchable(length) {
            return Err(Failed::Wrong("a file too large to fetch"));
        }
        let media_type = files::media_type(&facts.media_type).unwrap_or_else(|| "application/octet-stream".to_string());
        let mut remote = Remote { ask, length, media_type, groups: None, group: None };
        let chunks = chunk_count(length);
        let checked = if chunks == 0 {
            // No chunks: the id is that of no hashes at all, and nothing is asked.
            files::id_from_leaves(length, &[])
        } else if chunks <= FANOUT as u64 {
            let leaves = remote.ask_hashes(true, 0, chunks)?;
            let id = files::id_from_leaves(length, &leaves);
            remote.group = Some((0, leaves));
            id
        } else {
            let groups = remote.ask_hashes(false, 0, group_count(length))?;
            let id = files::id_from_groups(length, &groups);
            remote.groups = Some(groups);
            id
        };
        if checked != Some(*id) {
            return Err(Failed::Wrong("the hashes sent are not those of that file"));
        }
        Ok(remote)
    }

    /// The file's length, checked against its id.
    pub(crate) fn length(&self) -> u64 {
        self.length
    }

    /// The media type the other ship gives, as checked at upload; anything that check refuses
    /// is `application/octet-stream`.
    pub(crate) fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Ask for hashes, chunk hashes of group `index` or (not `leaves`) every group's index
    /// hash, which must be exactly `count`.
    fn ask_hashes(&mut self, leaves: bool, index: u64, count: u64) -> Result<Vec<[u8; 32]>, Failed> {
        let answer = match leaves {
            true => (self.ask)(peer_request::Body::FileLeaves(wanted(index)))?,
            false => (self.ask)(peer_request::Body::FileUpper(wanted(0)))?,
        };
        let sent = match (leaves, answer) {
            (true, peer_reply::Body::FileLeaves(sent)) | (false, peer_reply::Body::FileUpper(sent)) => sent,
            _ => return Err(Failed::Wrong("a reply of the wrong kind")),
        };
        if !sent.denied.is_empty() {
            return Err(Failed::Refused);
        }
        hashes(&sent.hashes, count).ok_or(Failed::Wrong("hashes sent are not as many as the file has"))
    }

    /// The checked hash of chunk `n`, fetching its group's hashes if they are not held, and
    /// checking them against the index hash for that group.
    fn leaf(&mut self, n: u64) -> Result<[u8; 32], Failed> {
        let g = n / FANOUT as u64;
        if self.group.as_ref().map(|(held, _)| *held) != Some(g) {
            let count = group_len(self.length, g).ok_or(Failed::Wrong("no such chunk"))?;
            // A second group is fetched only for a file of more than one, whose index hashes
            // were checked against the id.
            let expected = self.groups.as_ref().and_then(|groups| groups.get(g as usize).copied()).ok_or(Failed::Wrong("no such group"))?;
            self.group = None;
            let leaves = self.ask_hashes(true, g, count)?;
            if group_hash(&leaves) != expected {
                return Err(Failed::Wrong("the hashes sent are not those of that file"));
            }
            self.group = Some((g, leaves));
        }
        let (_, leaves) = self.group.as_ref().expect("held above");
        leaves.get((n % FANOUT as u64) as usize).copied().ok_or(Failed::Wrong("no such chunk"))
    }

    /// Chunk `n`, fetched and checked: exactly as long as the file's length says, and hashing
    /// to its checked hash. Nothing else is ever returned.
    pub(crate) fn chunk(&mut self, n: u64) -> Result<Vec<u8>, Failed> {
        let len = chunk_len(self.length, n).ok_or(Failed::Wrong("no such chunk"))?;
        let leaf = self.leaf(n)?;
        let peer_reply::Body::FileChunk(sent) = (self.ask)(peer_request::Body::FileChunk(wanted(n)))? else {
            return Err(Failed::Wrong("a reply of the wrong kind"));
        };
        if !sent.denied.is_empty() {
            return Err(Failed::Refused);
        }
        if sent.data.len() as u64 != len || files::leaf(&sent.data) != leaf {
            return Err(Failed::Wrong("a chunk sent is not that chunk of that file"));
        }
        Ok(sent.data)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sha2::{Digest, Sha256};
    use ship_proto::{FileBytes, FileFacts, FileHashes};

    use super::*;
    use crate::files::{file_id, leaf, CHUNK};

    /// A pretend ship that answers from made-up hashes, counting what it is asked.
    struct Pretend {
        length: u64,
        media_type: String,
        leaves: Vec<[u8; 32]>,
        chunks: HashMap<u64, Vec<u8>>,
        asked: Vec<String>,
    }

    impl Pretend {
        fn answer(&mut self, body: peer_request::Body) -> Result<peer_reply::Body, Failed> {
            Ok(match body {
                peer_request::Body::FileAbout(_) => {
                    self.asked.push("about".into());
                    peer_reply::Body::FileAbout(FileFacts { denied: String::new(), length: self.length, media_type: self.media_type.clone() })
                }
                peer_request::Body::FileLeaves(wanted) => {
                    self.asked.push(format!("leaves {}", wanted.index));
                    let from = wanted.index as usize * FANOUT;
                    let to = (from + FANOUT).min(self.leaves.len());
                    peer_reply::Body::FileLeaves(FileHashes { denied: String::new(), hashes: self.leaves[from..to].concat() })
                }
                peer_request::Body::FileUpper(_) => {
                    self.asked.push("upper".into());
                    peer_reply::Body::FileUpper(FileHashes { denied: String::new(), hashes: self.leaves.chunks(FANOUT).map(group_hash).collect::<Vec<_>>().concat() })
                }
                peer_request::Body::FileChunk(wanted) => {
                    self.asked.push(format!("chunk {}", wanted.index));
                    peer_reply::Body::FileChunk(FileBytes { denied: String::new(), data: self.chunks.get(&wanted.index).cloned().unwrap_or_default() })
                }
                _ => unreachable!(),
            })
        }
    }

    fn made_up(n: u32) -> [u8; 32] {
        Sha256::digest(n.to_le_bytes()).into()
    }

    /// A file one chunk past what one group holds: 32 GiB and a byte, whose last chunk is one
    /// byte. Its chunk hashes but the last are made up, so nothing of 32 GiB is ever hashed;
    /// the last chunk is real, and its hash is its own.
    fn across_a_level() -> (Pretend, [u8; 32]) {
        let length = FANOUT as u64 * CHUNK + 1;
        let mut leaves: Vec<[u8; 32]> = (0..FANOUT as u32).map(made_up).collect();
        leaves.push(leaf(b"x"));
        let id = file_id(length, &crate::files::root(&leaves));
        let chunks = HashMap::from([(FANOUT as u64, b"x".to_vec())]);
        (Pretend { length, media_type: "Text/Plain".into(), leaves, chunks, asked: Vec::new() }, id)
    }

    #[test]
    fn a_file_of_more_chunks_than_one_group_is_checked_through_the_level_above() {
        let (mut pretend, id) = across_a_level();
        let mut remote = Remote::open(|body| pretend.answer(body), &id).unwrap();
        assert_eq!((remote.length(), remote.media_type()), (FANOUT as u64 * CHUNK + 1, "text/plain"));
        // The last chunk: its group is fetched, checked against the index hash checked with
        // the id, and the chunk against its hash. The first group, 1 MiB of hashes, is never
        // asked for.
        assert_eq!(remote.chunk(FANOUT as u64).unwrap(), b"x");
        assert!(remote.chunk(FANOUT as u64 + 1).is_err());
        drop(remote);
        assert_eq!(pretend.asked, ["about", "upper", "leaves 1", &format!("chunk {FANOUT}")]);
    }

    #[test]
    fn hashes_across_a_level_that_do_not_hold_are_never_believed() {
        // The index hashes sent are not the file's.
        let (mut pretend, id) = across_a_level();
        let wrong = file_id(pretend.length + 1, &crate::files::root(&pretend.leaves));
        assert_eq!(Remote::open(|body| pretend.answer(body), &wrong).err(), Some(Failed::Wrong("the hashes sent are not those of that file")));
        // One group's chunk hashes are not those its index hash stands for.
        let (mut pretend, _) = across_a_level();
        let mut changed = true;
        let mut remote = Remote::open(
            |body| {
                let mut answer = pretend.answer(body)?;
                if let peer_reply::Body::FileLeaves(sent) = &mut answer {
                    sent.hashes[0] ^= u8::from(std::mem::take(&mut changed));
                }
                Ok(answer)
            },
            &id,
        )
        .unwrap();
        assert_eq!(remote.chunk(FANOUT as u64).err(), Some(Failed::Wrong("the hashes sent are not those of that file")));
        // One index hash too few, or one too many.
        for take in [1usize, 3] {
            let (mut pretend, id) = across_a_level();
            let opened = Remote::open(
                |body| {
                    let mut answer = pretend.answer(body)?;
                    if let peer_reply::Body::FileUpper(sent) = &mut answer {
                        sent.hashes.resize(take * 32, 7);
                    }
                    Ok(answer)
                },
                &id,
            );
            assert_eq!(opened.err(), Some(Failed::Wrong("hashes sent are not as many as the file has")), "{take}");
        }
    }

    #[test]
    fn a_length_that_needs_more_than_two_levels_is_not_asked_about() {
        let length = (FANOUT as u64 * FANOUT as u64 + 1) * CHUNK;
        let mut asked = 0;
        let opened = Remote::open(
            |_| {
                asked += 1;
                Ok(peer_reply::Body::FileAbout(FileFacts { denied: String::new(), length, media_type: String::new() }))
            },
            &[0; 32],
        );
        assert_eq!(opened.err(), Some(Failed::Wrong("a file too large to fetch")));
        assert_eq!(asked, 1);
        // The largest length there is is no different.
        let opened = Remote::open(|_| Ok(peer_reply::Body::FileAbout(FileFacts { denied: String::new(), length: u64::MAX, media_type: String::new() })), &[0; 32]);
        assert_eq!(opened.err(), Some(Failed::Wrong("a file too large to fetch")));
    }

    #[test]
    fn a_refusal_is_only_a_no() {
        let denied = format!("<script>no</script>\r\nSet-Cookie: x{}", "y".repeat(1000));
        let opened = Remote::open(|_| Ok(peer_reply::Body::FileAbout(FileFacts { denied: denied.clone(), length: 0, media_type: String::new() })), &[0; 32]);
        assert_eq!(opened.err(), Some(Failed::Refused));
    }
}
