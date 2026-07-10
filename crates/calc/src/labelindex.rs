//! Incremental selector→member membership index with label inheritance.
//!
//! This is the Rust counterpart of upstream Felix's
//! `felix/labelindex` (`InheritIndex` + `SelectorAndNamedPortIndex`): the data
//! structure that answers "which endpoints match selector S, and therefore
//! which member IPs form IP-set S", updating **incrementally** (emitting only
//! the members that joined/left) as items, parents, and selectors change.
//!
//! # Model
//!
//! - **Items** (endpoints) have an id, their OWN labels, a set of member
//!   contributions (IP addresses / CIDRs), and a list of PARENT ids
//!   (profiles / namespaces) they inherit labels from.
//! - **Parents** (profiles / namespaces) have their own labels.
//! - **Selectors** are registered under an IP-set id; each resolves to the set
//!   of items whose EFFECTIVE labels match.
//!
//! # Label inheritance
//!
//! An item's EFFECTIVE labels are the merge of its parents' labels with its own
//! labels, where **own labels win** on a key conflict and, among parents,
//! **earlier parents win** over later ones. This matches upstream
//! `label_inheritance_index.go` (`itemData.GetHandle`: own labels first, then
//! parents in order, returning the first match). When a parent's labels change,
//! every item referencing that parent is re-evaluated.
//!
//! # Reference-counted membership
//!
//! Within an IP-set, each member IP carries a reference count: an IP
//! contributed by two matching items is only removed once BOTH stop
//! contributing it. This mirrors upstream `ipSetData.memberToRefCount`.
//!
//! # Deltas
//!
//! Every mutating call returns a [`Vec<Delta>`] describing exactly the members
//! that joined ([`MemberChange::Added`], on a `0 -> 1` ref-count transition) or
//! left ([`MemberChange::Removed`], on a `1 -> 0` transition) each affected
//! IP-set. No full re-list is emitted.
//!
//! # Named ports
//!
//! Upstream's index also produces named-port members `(ip, port, proto)`. That
//! path is **deferred** here: this index implements plain IP/CIDR membership
//! fully, which is what IP-set computation (T052) needs first. See the note on
//! [`MembershipIndex`] for the extension point.

use std::collections::{BTreeMap, BTreeSet};

use crate::selector::Selector;

/// Item (endpoint) identifier.
pub type ItemId = String;
/// Parent (profile / namespace) identifier.
pub type ParentId = String;
/// IP-set (selector) identifier.
pub type IpSetId = String;
/// A member contribution: an IP address or CIDR, as a string.
///
/// Named-port members are deferred (see the module docs); when added they would
/// become a richer enum here.
pub type Member = String;

/// Whether a member joined or left an IP-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberChange {
    /// The member joined the IP-set (ref-count `0 -> 1`).
    Added,
    /// The member left the IP-set (ref-count `1 -> 0`).
    Removed,
}

/// A single incremental change to an IP-set's membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    /// The IP-set (selector) affected.
    pub ip_set_id: IpSetId,
    /// The member IP/CIDR that joined or left.
    pub member: Member,
    /// Whether the member joined or left.
    pub change: MemberChange,
}

#[derive(Debug, Default)]
struct ItemData {
    own_labels: BTreeMap<String, String>,
    parents: Vec<ParentId>,
    members: BTreeSet<Member>,
}

#[derive(Debug, Default)]
struct ParentData {
    labels: BTreeMap<String, String>,
    item_ids: BTreeSet<ItemId>,
}

#[derive(Debug)]
struct SelectorData {
    selector: Selector,
    /// Ref-count per member IP; a member is present iff its count is `>= 1`.
    member_ref_counts: BTreeMap<Member, usize>,
    /// Items currently matching this selector.
    matching_items: BTreeSet<ItemId>,
}

/// An incremental selector→member membership index with label inheritance.
///
/// Named-port membership is deferred (module docs); [`Member`] is a plain
/// IP/CIDR string today.
#[derive(Debug, Default)]
pub struct MembershipIndex {
    items: BTreeMap<ItemId, ItemData>,
    parents: BTreeMap<ParentId, ParentData>,
    selectors: BTreeMap<IpSetId, SelectorData>,
}

impl MembershipIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace an item, returning the resulting membership deltas.
    pub fn update_item(
        &mut self,
        id: impl Into<ItemId>,
        own_labels: BTreeMap<String, String>,
        parents: Vec<ParentId>,
        members: BTreeSet<Member>,
    ) -> Vec<Delta> {
        let id = id.into();

        // Snapshot the previous contribution before we overwrite it.
        let old_members = self
            .items
            .get(&id)
            .map(|d| d.members.clone())
            .unwrap_or_default();
        let old_parents = self
            .items
            .get(&id)
            .map(|d| d.parents.clone())
            .unwrap_or_default();

        // Maintain the parent -> item back-references.
        self.update_parent_refs(&id, &old_parents, &parents);

        self.items.insert(
            id.clone(),
            ItemData {
                own_labels,
                parents,
                members: members.clone(),
            },
        );

        let eff = self.effective_labels(&id);
        let mut deltas = Vec::new();
        for sel_id in self.selector_ids() {
            let sd = self.selectors.get_mut(&sel_id).expect("selector exists");
            let was = sd.matching_items.contains(&id);
            let now = sd.selector.matches(&eff);
            sd.reconcile(
                &sel_id,
                &id,
                Contribution {
                    matching: was,
                    members: &old_members,
                },
                Contribution {
                    matching: now,
                    members: &members,
                },
                &mut deltas,
            );
        }
        deltas
    }

    /// Remove an item, returning the resulting membership deltas.
    pub fn delete_item(&mut self, id: &str) -> Vec<Delta> {
        let Some(old) = self.items.remove(id) else {
            return Vec::new();
        };
        self.update_parent_refs(id, &old.parents, &[]);

        let empty = BTreeSet::new();
        let mut deltas = Vec::new();
        for sel_id in self.selector_ids() {
            let sd = self.selectors.get_mut(&sel_id).expect("selector exists");
            let was = sd.matching_items.contains(id);
            sd.reconcile(
                &sel_id,
                id,
                Contribution {
                    matching: was,
                    members: &old.members,
                },
                Contribution {
                    matching: false,
                    members: &empty,
                },
                &mut deltas,
            );
        }
        deltas
    }

    /// Insert or replace a parent's labels, re-evaluating every item that
    /// references it. Returns the resulting membership deltas.
    pub fn update_parent(
        &mut self,
        id: impl Into<ParentId>,
        labels: BTreeMap<String, String>,
    ) -> Vec<Delta> {
        let id = id.into();
        self.parents.entry(id.clone()).or_default().labels = labels;
        self.reeval_parent_children(&id)
    }

    /// Remove a parent's labels, re-evaluating referencing items. The parent
    /// record is dropped once no items reference it.
    pub fn delete_parent(&mut self, id: &str) -> Vec<Delta> {
        if !self.parents.contains_key(id) {
            return Vec::new();
        }
        if let Some(p) = self.parents.get_mut(id) {
            p.labels = BTreeMap::new();
        }
        let deltas = self.reeval_parent_children(id);
        self.discard_parent_if_empty(id);
        deltas
    }

    /// Register a selector under an IP-set id, immediately yielding the members
    /// of all items that currently match.
    pub fn add_selector(
        &mut self,
        ip_set_id: impl Into<IpSetId>,
        selector: Selector,
    ) -> Vec<Delta> {
        let ip_set_id = ip_set_id.into();
        self.selectors.insert(
            ip_set_id.clone(),
            SelectorData {
                selector,
                member_ref_counts: BTreeMap::new(),
                matching_items: BTreeSet::new(),
            },
        );

        let empty = BTreeSet::new();
        let mut deltas = Vec::new();
        for item_id in self.item_ids() {
            let eff = self.effective_labels(&item_id);
            let members = &self.items[&item_id].members;
            let sd = self.selectors.get_mut(&ip_set_id).expect("just inserted");
            let now = sd.selector.matches(&eff);
            sd.reconcile(
                &ip_set_id,
                &item_id,
                Contribution {
                    matching: false,
                    members: &empty,
                },
                Contribution {
                    matching: now,
                    members,
                },
                &mut deltas,
            );
        }
        deltas
    }

    /// Remove a selector, yielding a removal for every current member.
    pub fn remove_selector(&mut self, ip_set_id: &str) -> Vec<Delta> {
        let Some(sd) = self.selectors.remove(ip_set_id) else {
            return Vec::new();
        };
        sd.member_ref_counts
            .into_keys()
            .map(|member| Delta {
                ip_set_id: ip_set_id.to_string(),
                member,
                change: MemberChange::Removed,
            })
            .collect()
    }

    /// The current members of an IP-set (empty if unknown).
    pub fn members(&self, ip_set_id: &str) -> BTreeSet<Member> {
        self.selectors
            .get(ip_set_id)
            .map(|sd| sd.member_ref_counts.keys().cloned().collect())
            .unwrap_or_default()
    }

    // ---- internals -------------------------------------------------------

    fn selector_ids(&self) -> Vec<IpSetId> {
        self.selectors.keys().cloned().collect()
    }

    fn item_ids(&self) -> Vec<ItemId> {
        self.items.keys().cloned().collect()
    }

    /// Effective labels of an item: parent labels merged with own labels, where
    /// own labels win and, among parents, earlier parents win over later ones.
    fn effective_labels(&self, id: &str) -> BTreeMap<String, String> {
        let mut merged = BTreeMap::new();
        let Some(item) = self.items.get(id) else {
            return merged;
        };
        // Insert parents last-to-first so that earlier parents overwrite later.
        for pid in item.parents.iter().rev() {
            if let Some(p) = self.parents.get(pid) {
                for (k, v) in &p.labels {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        // Own labels win over all parents.
        for (k, v) in &item.own_labels {
            merged.insert(k.clone(), v.clone());
        }
        merged
    }

    /// Re-evaluate every item referencing `parent_id` against every selector.
    /// Member sets are unchanged, so only match-status transitions emit deltas.
    fn reeval_parent_children(&mut self, parent_id: &str) -> Vec<Delta> {
        let item_ids: Vec<ItemId> = self
            .parents
            .get(parent_id)
            .map(|p| p.item_ids.iter().cloned().collect())
            .unwrap_or_default();

        let mut deltas = Vec::new();
        for item_id in item_ids {
            let eff = self.effective_labels(&item_id);
            let members = self.items[&item_id].members.clone();
            for sel_id in self.selector_ids() {
                let sd = self.selectors.get_mut(&sel_id).expect("selector exists");
                let was = sd.matching_items.contains(&item_id);
                let now = sd.selector.matches(&eff);
                sd.reconcile(
                    &sel_id,
                    &item_id,
                    Contribution {
                        matching: was,
                        members: &members,
                    },
                    Contribution {
                        matching: now,
                        members: &members,
                    },
                    &mut deltas,
                );
            }
        }
        deltas
    }

    /// Update parent -> item back-references when an item's parent list changes,
    /// creating parents on demand and discarding now-empty ones.
    fn update_parent_refs(
        &mut self,
        item_id: &str,
        old_parents: &[ParentId],
        new_parents: &[ParentId],
    ) {
        for pid in old_parents {
            if new_parents.contains(pid) {
                continue;
            }
            if let Some(p) = self.parents.get_mut(pid) {
                p.item_ids.remove(item_id);
            }
            self.discard_parent_if_empty(pid);
        }
        for pid in new_parents {
            self.parents
                .entry(pid.clone())
                .or_default()
                .item_ids
                .insert(item_id.to_string());
        }
    }

    /// Drop a parent record that has neither labels nor referencing items.
    fn discard_parent_if_empty(&mut self, id: &str) {
        if let Some(p) = self.parents.get(id) {
            if p.item_ids.is_empty() && p.labels.is_empty() {
                self.parents.remove(id);
            }
        }
    }
}

/// An item's contribution to a selector: whether it matched, and the member set
/// it offered while matching.
struct Contribution<'a> {
    matching: bool,
    members: &'a BTreeSet<Member>,
}

impl SelectorData {
    /// Reconcile a single item's contribution given its old and new state.
    /// Ref-count transitions (`0 -> 1`, `1 -> 0`) are appended to `deltas`.
    fn reconcile(
        &mut self,
        ip_set_id: &str,
        item_id: &str,
        old: Contribution,
        new: Contribution,
        deltas: &mut Vec<Delta>,
    ) {
        let empty = BTreeSet::new();
        let old_contrib = if old.matching { old.members } else { &empty };
        let new_contrib = if new.matching { new.members } else { &empty };

        for member in old_contrib.difference(new_contrib) {
            if let Some(count) = self.member_ref_counts.get_mut(member) {
                *count -= 1;
                if *count == 0 {
                    self.member_ref_counts.remove(member);
                    deltas.push(Delta {
                        ip_set_id: ip_set_id.to_string(),
                        member: member.clone(),
                        change: MemberChange::Removed,
                    });
                }
            }
        }
        for member in new_contrib.difference(old_contrib) {
            let count = self.member_ref_counts.entry(member.clone()).or_insert(0);
            *count += 1;
            if *count == 1 {
                deltas.push(Delta {
                    ip_set_id: ip_set_id.to_string(),
                    member: member.clone(),
                    change: MemberChange::Added,
                });
            }
        }

        if new.matching {
            self.matching_items.insert(item_id.to_string());
        } else {
            self.matching_items.remove(item_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn members(items: &[&str]) -> BTreeSet<Member> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn sel(s: &str) -> Selector {
        Selector::parse(s).unwrap()
    }

    /// Assert a delta set equals the expected (ip_set, member, change) triples,
    /// order-independent.
    fn assert_deltas(got: Vec<Delta>, want: &[(&str, &str, MemberChange)]) {
        let mut got: Vec<(String, String, MemberChange)> = got
            .into_iter()
            .map(|d| (d.ip_set_id, d.member, d.change))
            .collect();
        got.sort_by_key(|t| (t.0.clone(), t.1.clone()));
        let mut want: Vec<(String, String, MemberChange)> = want
            .iter()
            .map(|(s, m, c)| (s.to_string(), m.to_string(), *c))
            .collect();
        want.sort_by_key(|t| (t.0.clone(), t.1.clone()));
        assert_eq!(got, want);
    }

    #[test]
    fn item_matching_selector_contributes_members_then_deleted() {
        let mut idx = MembershipIndex::new();
        idx.add_selector("s", sel("role == 'web'"));

        let d = idx.update_item(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1"]),
        );
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Added)]);
        assert_eq!(idx.members("s"), members(&["10.0.0.1"]));

        let d = idx.delete_item("ep1");
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Removed)]);
        assert!(idx.members("s").is_empty());
    }

    #[test]
    fn non_matching_item_contributes_nothing() {
        let mut idx = MembershipIndex::new();
        idx.add_selector("s", sel("role == 'web'"));
        let d = idx.update_item(
            "ep1",
            labels(&[("role", "db")]),
            vec![],
            members(&["10.0.0.1"]),
        );
        assert!(d.is_empty());
        assert!(idx.members("s").is_empty());
    }

    #[test]
    fn refcount_shared_ip_removed_only_after_both_leave() {
        let mut idx = MembershipIndex::new();
        idx.add_selector("s", sel("role == 'web'"));

        let d = idx.update_item(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1"]),
        );
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Added)]);
        // Second endpoint contributes the same IP: no new Added (ref-count 1 -> 2).
        let d = idx.update_item(
            "ep2",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1"]),
        );
        assert!(d.is_empty());
        assert_eq!(idx.members("s"), members(&["10.0.0.1"]));

        // First leaves: still held by ep2, no Removed.
        let d = idx.delete_item("ep1");
        assert!(d.is_empty());
        assert_eq!(idx.members("s"), members(&["10.0.0.1"]));

        // Second leaves: now removed.
        let d = idx.delete_item("ep2");
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Removed)]);
        assert!(idx.members("s").is_empty());
    }

    #[test]
    fn label_inheritance_from_parent() {
        let mut idx = MembershipIndex::new();
        idx.add_selector("s", sel("b == '2'"));
        idx.update_parent("prof", labels(&[("b", "2")]));

        // Item has no own b label but inherits b=2 from parent.
        let d = idx.update_item(
            "ep1",
            labels(&[("a", "1")]),
            vec!["prof".into()],
            members(&["10.0.0.1"]),
        );
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Added)]);
    }

    #[test]
    fn parent_label_change_reevaluates_items() {
        let mut idx = MembershipIndex::new();
        idx.add_selector("s", sel("b == '2'"));
        idx.update_item(
            "ep1",
            labels(&[("a", "1")]),
            vec!["prof".into()],
            members(&["10.0.0.1"]),
        );
        // Parent doesn't have b yet: no match.
        assert!(idx.members("s").is_empty());

        // Parent gains b=2: item now matches, member joins.
        let d = idx.update_parent("prof", labels(&[("b", "2")]));
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Added)]);

        // Parent changes b: item no longer matches, member leaves.
        let d = idx.update_parent("prof", labels(&[("b", "3")]));
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Removed)]);
    }

    #[test]
    fn parent_deletion_reevaluates_items() {
        let mut idx = MembershipIndex::new();
        idx.add_selector("s", sel("b == '2'"));
        idx.update_parent("prof", labels(&[("b", "2")]));
        idx.update_item(
            "ep1",
            labels(&[("a", "1")]),
            vec!["prof".into()],
            members(&["10.0.0.1"]),
        );
        assert_eq!(idx.members("s"), members(&["10.0.0.1"]));

        let d = idx.delete_parent("prof");
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Removed)]);
    }

    #[test]
    fn own_label_overrides_parent_label() {
        let mut idx = MembershipIndex::new();
        idx.update_parent("prof", labels(&[("k", "parent")]));
        // Selector wants the parent's value; own label overrides so it must NOT match.
        idx.add_selector("parent_match", sel("k == 'parent'"));
        idx.add_selector("own_match", sel("k == 'own'"));

        let d = idx.update_item(
            "ep1",
            labels(&[("k", "own")]),
            vec!["prof".into()],
            members(&["10.0.0.1"]),
        );
        assert_deltas(d, &[("own_match", "10.0.0.1", MemberChange::Added)]);
        assert!(idx.members("parent_match").is_empty());
        assert_eq!(idx.members("own_match"), members(&["10.0.0.1"]));
    }

    #[test]
    fn earlier_parent_wins_over_later_parent() {
        let mut idx = MembershipIndex::new();
        idx.update_parent("p1", labels(&[("k", "first")]));
        idx.update_parent("p2", labels(&[("k", "second")]));
        idx.add_selector("first", sel("k == 'first'"));
        idx.add_selector("second", sel("k == 'second'"));

        let d = idx.update_item(
            "ep1",
            BTreeMap::new(),
            vec!["p1".into(), "p2".into()],
            members(&["10.0.0.1"]),
        );
        assert_deltas(d, &[("first", "10.0.0.1", MemberChange::Added)]);
        assert_eq!(idx.members("first"), members(&["10.0.0.1"]));
        assert!(idx.members("second").is_empty());
    }

    #[test]
    fn add_selector_after_items_yields_current_members() {
        let mut idx = MembershipIndex::new();
        idx.update_item(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1"]),
        );
        idx.update_item(
            "ep2",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.2"]),
        );
        idx.update_item(
            "ep3",
            labels(&[("role", "db")]),
            vec![],
            members(&["10.0.0.3"]),
        );

        let d = idx.add_selector("s", sel("role == 'web'"));
        assert_deltas(
            d,
            &[
                ("s", "10.0.0.1", MemberChange::Added),
                ("s", "10.0.0.2", MemberChange::Added),
            ],
        );
        assert_eq!(idx.members("s"), members(&["10.0.0.1", "10.0.0.2"]));
    }

    #[test]
    fn remove_selector_clears_members() {
        let mut idx = MembershipIndex::new();
        idx.update_item(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1"]),
        );
        idx.add_selector("s", sel("role == 'web'"));
        assert_eq!(idx.members("s"), members(&["10.0.0.1"]));

        let d = idx.remove_selector("s");
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Removed)]);
        assert!(idx.members("s").is_empty());
    }

    #[test]
    fn item_label_change_moves_membership() {
        let mut idx = MembershipIndex::new();
        idx.add_selector("web", sel("role == 'web'"));
        idx.add_selector("db", sel("role == 'db'"));

        idx.update_item(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1"]),
        );
        assert_eq!(idx.members("web"), members(&["10.0.0.1"]));

        // Relabel: leaves web, joins db — exactly one Removed and one Added.
        let d = idx.update_item(
            "ep1",
            labels(&[("role", "db")]),
            vec![],
            members(&["10.0.0.1"]),
        );
        assert_deltas(
            d,
            &[
                ("web", "10.0.0.1", MemberChange::Removed),
                ("db", "10.0.0.1", MemberChange::Added),
            ],
        );
    }

    #[test]
    fn member_change_while_matching_emits_only_the_diff() {
        let mut idx = MembershipIndex::new();
        idx.add_selector("s", sel("role == 'web'"));
        idx.update_item(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1"]),
        );

        // Add a second IP, keep the first: only the new IP is a delta.
        let d = idx.update_item(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1", "10.0.0.2"]),
        );
        assert_deltas(d, &[("s", "10.0.0.2", MemberChange::Added)]);

        // Drop the first IP: only that IP leaves.
        let d = idx.update_item(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.2"]),
        );
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Removed)]);
        assert_eq!(idx.members("s"), members(&["10.0.0.2"]));
    }

    #[test]
    fn unchanged_item_update_emits_no_deltas() {
        let mut idx = MembershipIndex::new();
        idx.add_selector("s", sel("role == 'web'"));
        idx.update_item(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1"]),
        );
        let d = idx.update_item(
            "ep1",
            labels(&[("role", "web")]),
            vec![],
            members(&["10.0.0.1"]),
        );
        assert!(d.is_empty());
    }

    #[test]
    fn all_selector_matches_every_item() {
        let mut idx = MembershipIndex::new();
        idx.add_selector("s", sel("all()"));
        let d = idx.update_item("ep1", BTreeMap::new(), vec![], members(&["10.0.0.1"]));
        assert_deltas(d, &[("s", "10.0.0.1", MemberChange::Added)]);
    }
}
