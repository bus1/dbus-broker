//! # Resource Accounting
//!
//! To safely communicate across user boundaries, the broker needs to apply
//! quotas to pinned resources, so no user can exploit all resources of
//! another. This resource accounting system provides a global context to
//! assign resource limits to each user, and then track all resource charges.
//!
//! To achieve this, the system strictly separates individual users from each
//! other. Every user get a resource limit assigned, and can never exceed
//! this limit.
//!
//! While users provide the resource accounting, any active charge is performed
//! by an actor. Those always operate on behalf of a user, and then can charge
//! resources either on their own user, or on other users.
//!
//! The accounting system ensures that dynamic quotas are applied and thus
//! grant all users a fair share of the available resources. The exact
//! algorithm is not part of the API guarantee, and thus a programmatic test
//! of the resource limits is not a valid use of the API. Instead, resource
//! limits are applied similar to mandatory access control: they ensure safe
//! operation, and should only ever affect unexpected or malicious operations.
//!
//! ## Examples
//!
//! A simple example that creates a resource system with 2 users and actors,
//! and charges resources on each.
//!
//! ```
//! use rbus::util::acct;
//! let acct = acct::Acct::new(&[1024; acct::N_SLOTS]);
//! ```

use alloc::{collections::btree_map, rc};
use core::{cell, convert};
use rbus_generated::util_acct;

/// Representation of user IDs in the accounting system. This is guaranteed to
/// be a primitive unsigned integer big enough to hold Linux UIDs. Currently
/// set to `u32`.
pub type Id = util_acct::acct_id_t;

/// Representation of resource counters in the accounting system. This is
/// guaranteed to be a primitive unsigned integer. Currently set to `u64`.
pub type Value = util_acct::acct_value_t;

/// Number of resource slots in the accounting system. That is, it defines how
/// many different (and independent) resource types are in use and tracked by
/// the accounting system.
pub const N_SLOTS: usize = util_acct::_ACCT_SLOT_N;

/// An object to track how many resources a stage has available and claimed.
///
/// A [`Claim`] object is always attached to an entity that claims resources
/// (regardless whether it is a tail-node or an intermediate that re-shares
/// the resources). It tracks how many resources this entity currently has
/// claimed from its upper node, and how many it has available to its lower
/// nodes. The amount it granted to its lower nodes is the difference between
/// the two.
///
/// Tail nodes should never have resources available. They should always
/// request exactly the amount they claim, and they should always release all
/// resources back to the upper node if no longer needed.
///
/// Intermediate nodes will likely request more resources than they grant.
/// This allows guarantees to other sub-nodes about future resource claims,
/// without being required to request more from the upper nodes (which can
/// possibly fail).
///
/// The root node cannot release resource to upper nodes (there are no upper
/// nodes), and thus the available resource of the root node show exactly
/// the resources that have not been claimed by the system, yet.
struct Claim {
    available: [Value; N_SLOTS],
    claimed: [Value; N_SLOTS],
}

struct AcctInner {
    users: btree_map::BTreeMap<Id, rc::Weak<User>>,
    maxima: [Value; N_SLOTS],
}

/// The root context of an independent accounting system.
///
/// All objects of the module are eventually tied to one [`Acct`] object.
/// Different such objects are fully independent.
///
/// The root context is used to gain access to [`User`] and [`Actor`] objects,
/// and provides the initial resource constraints of the system.
pub struct Acct {
    inner: cell::RefCell<AcctInner>,
}

struct UserInner {
    quotas: btree_map::BTreeMap<Id, rc::Weak<Quota>>,
    maxima: [Value; N_SLOTS],
    claim: Claim,
}

/// A user is an independent entity of the accounting system with a fixed
/// resource limit.
///
/// The resource system is partitioned into independent users, which operate
/// fully independently.
///
/// An [`Actor`] can then claim resources of a user up to the limit of the
/// user. If the actor is tied to the user it claims from, then it can claim up
/// to the resource limit. If the actor is tied to another user, then its
/// resource claims are subject to a quota.
pub struct User {
    acct: rc::Rc<Acct>,
    id: Id,
    inner: cell::RefCell<UserInner>,
}

/// An actor is an entity of the accounting system that can lay claims on
/// resources.
///
/// Actors always operate on behalf of a user. Actors can either claim
/// resources of their own user, or of other users. In case of the latter,
/// the claim is subject to a quota.
pub struct Actor {
    user: rc::Rc<User>,
}

struct QuotaInner {
    traces: btree_map::BTreeMap<*const Actor, rc::Weak<Trace>>,
    claim: Claim,
}

struct Quota {
    user: rc::Rc<User>,
    id: Id,
    inner: cell::RefCell<QuotaInner>,
}

struct TraceInner {
    claim: Claim,
}

struct Trace {
    quota: rc::Rc<Quota>,
    actor: *const Actor,
    inner: cell::RefCell<TraceInner>,
}

struct ChargeInner {
    trace: Option<rc::Rc<Trace>>,
    amount: [Value; N_SLOTS],
}

/// An object to represent an active resource claim charged on the system.
pub struct Charge {
    inner: ChargeInner,
}

/// Calculate the ceiled base-2 logarithm, rounding up in case of missing
/// precision.
///
/// If `v` is 0, or negative, the function will produce a result, but does not
/// give guarantees on its value (currently, it will produce the maximum
/// logarithm representable).
fn log2_ceil(v: Value) -> Value {
    let length: u32 = Value::BITS;

    // This calculates the ceiled logarithm. What we do is count the leading
    // zeros of the value in question and then substract it from its
    // bit-length. By subtracting one from the value first we make sure the
    // value is ceiled.
    //
    // Hint: To calculate the floored value, you would do the subtraction of 1
    //       from the final value, rather than from the source value:
    //
    //           `length - v.leading_zeros() - 1`
    let log2: u32 = length - (v - 1).leading_zeros();

    // Convert the value back into the source type. Since the source type must
    // be an integer type, it must have a representation for all integers
    // between its original and 0. Hence, this cannot fail.
    convert::From::from(log2)
}

/// A resource allocator that provides exponential allocation guarantees. It
/// ensures resource reserves are freely accessible, at the expense of granting
/// only very limited guarantees to each entity.
///
/// This allocator grants access to half of the remaining resources for every
/// new allocation. As such, this allocator guarantees that each independent
/// entity gets access to 1 over `2^n` of the total resources.
pub fn allocator_exponential(_users: Value) -> Option<Value> {
    Some(2)
}

/// A resource allocator that provides polynomial allocation guarantees. It
/// ensures resource reserves are easily accessible, at the expense of granting
/// only limited guarantees to each entity.
///
/// This allocator grants access to 1 over `n` of the remaining resources for
/// every new allocation (with `n` being the number of active entities). As
/// such, this allocator guarantees that each independent entity gets access to
/// 1 over `n^2` of the total resources.
pub fn allocator_polynomial(users: Value) -> Option<Value> {
    users.checked_add(1)
}

/// A resource allocator that provides quasilinear allocation guarantees. It
/// ensures strong guarantees to each entity, at the expense of heavily
/// restricting resource reserves.
///
/// This allocator grants access to 1 over `n log(n) + n` of the remaining
/// resources for every new allocation (with `n` being the number of active
/// entities). As such, this allocator guarantees that each independent
/// entity gets access to 1 over `n log(n)^2` of the total resources.
pub fn allocator_quasilinear(users: Value) -> Option<Value> {
    let users1 = users.checked_add(1)?;
    let log_mul = log2_ceil(users1).checked_mul(users1)?;
    log_mul.checked_add(users1)
}

/// Calculate the minimum reserve size required for an allocation request to
/// pass the quota.
///
/// Whenever an allocation request is checked against the quota, this function
/// can be used to calculate how many resources must still be available in the
/// reserve to allow the request. If this minimum reserve size matches the size
/// of the request, the allocation would be allowed to consume all remaining
/// resources. In most cases, this function returns a bigger minimum reserve
/// size, to ensure future requests can be served as well.
///
/// This function implements an algorithm to allow an unknown set of users to
/// fairly share a fixed pool of resources. It considers the changing parameters
/// and adjusts its quota check accordingly, ensuring that a growing or
/// shrinking set of users get arbitrated access to the available resources
/// in a fair manner.
///
/// The quota-check is applied whenever a user requests resources from the
/// shared resource pool. The following information is involved in checking a
/// quota:
///
/// * `remaining`: Amount of resources that are available for allocation
/// * `n_users`: Number of users that are tracked, including the claimant user
/// * `share`: Amount of resources the claimant user has already allocated
/// * `charge`: Amount of resources that are requested by the claimant user
///
/// ## Algorithm
///
/// Ideally, every user on the system would get `1 / n_users` of the available
/// resources. This would be a fair system, where everyone gets the same share.
/// Unfortunately, we do not know the number of users that will participate
/// upfront. Hence, we use an algorithm that guarantees something that comes
/// close to this ideal.
///
/// An allocation that was granted is never revoked, nor do we reclaim any
/// resources that are actively used. Hence, the only place the algorithm is
/// applied is when an allocation is requested. There, we look at the amount
/// of resources that are still available, and then decide whether the user
/// is allowed their request. We consider every allocation of a user as a
/// `re-allocation` of their current share. That is, we pretend they release
/// their currently held resources, then request a new allocation that is the
/// size of the original request plus their previous share. This `re-allocation`
/// then has to satisfy the following inequality:
///
/// ```txt
///                       remaining + share
///     charge + share <= ~~~~~~~~~~~~~~~~~
///                           A(n_users)
/// ```
///
/// In other words, of the remaining resources, a user gets a fraction that
/// only depends on the number of users that are active. Now depending on which
/// function `A()` is chosen, a user can request more or less resources.
/// However, selection of `A()` also affects the overall guarantees that the
/// algorithm will provide.
///
/// For example, consider `A(n): 2`. That is, an allocator that always grants
/// half of the remaining resources to a user:
///
/// ```txt
///                       remaining + share
///     charge + share <= ~~~~~~~~~~~~~~~~~
///                               2
/// ```
///
/// This will ensure that resources are easily available and little reserves
/// are kept. However, for a single user, this allocation scheme can only
/// guarantee that each user gets `1 / 2^n` of the available resources. So
/// while it ensures that resources are easily available and not held back,
/// it also prevents any meaningful guarantess for a single user, and as such
/// denials of service can ensue.
///
/// If, on the other hand, you pick `A(n): n + 1`, then only a share
/// proportional to the number of currently active users is granted:
///
/// ```txt
///                       remaining + share
///     charge + share <= ~~~~~~~~~~~~~~~~~
///                          n_users + 1
/// ```
///
/// (Note that `n_users` is not the total numbers of users involved in the
/// system eventually, but merely at the given moment).
///
/// With this allocator, much bigger reserves are kept as the number of users
/// rises. Ultimately, this will guarantee that each users gets `1 / n^2` of
/// the total resources. This is already much better than the exponential
/// backoff of the previous allocator.
///
/// Now, lastly, we consider `A(n): n log(n) + n`, or more precicesly
/// `A(n): (n+1) log(n+1) + n+1`. With this allocator, resources are kept
/// even tighter, but ultimately we get a quasilinear guarantee for each user
/// with `1 / (n * log(n)^2)`. This is already pretty close to the ideal of
/// `1 / n`.
///
/// ## Hierarchy
///
/// The algorithm can be applied to a hierarchical setup by simply chaining
/// quota checks. For instance, one could first check whether a user can
/// allocate resources from a global resource pool, and then check whether a
/// claimant can allocate resources on that user. Depending on what guarantees
/// are desired on each level, different allocators can be chosen. However,
/// any hierarchical setup will also significantly reduce the guarantees, as
/// each level operates only on the guarantees of the previous level.
fn quota_reserve<F>(
    allocator_fn: F,
    n_users: Value,
    share: Value,
    charge: Value,
) -> Option<Value>
where
    F: Fn(Value) -> Option<Value>,
{
    // For a quota check, we have to calculate:
    //
    //                       remaining + share
    //     charge + share <= ~~~~~~~~~~~~~~~~~
    //                           A(n_users)
    //
    // But to avoid the division, we instead calculate:
    //
    //     (charge + share) * A(n_users) - share <= remaining
    //
    // The inequality itself has to be checked by the caller. This function
    // merely computes the left half of the inequality and returns it.
    //
    // None of these partial calculations exceed the actual limit by a factor
    // of 2, and as such we expect all calculations to be possible within the
    // limits of the integer type. Any overflow will thus result in a quota
    // rejection.

    let allocator = allocator_fn(n_users)?;
    let charge_share = charge.checked_add(share)?;
    let limit = charge_share.checked_mul(allocator)?;
    let minimum = limit.checked_sub(share)?;

    Some(minimum)
}

/// Search a map of weak-refs for an entry with the given key. Upgrade to a
/// strong-ref and return it. If either the upgrade fails, or if the key is
/// not present, use `insert_fn` to insert a new entry, and return it.
fn find_and_upgrade_or_insert_with<K, V, F>(
    map: &mut btree_map::BTreeMap<K, rc::Weak<V>>,
    key: &K,
    insert_fn: F,
) -> rc::Rc<V>
where
    K: Clone + Ord,
    F: FnOnce() -> rc::Rc<V>,
{
    match map.entry(key.clone()) {
        btree_map::Entry::Vacant(vac) => {
            let v = insert_fn();
            vac.insert(rc::Rc::downgrade(&v));
            v
        },
        btree_map::Entry::Occupied(mut occ) => {
            if let Some(v) = occ.get().upgrade() {
                v
            } else {
                let v = insert_fn();
                occ.insert(rc::Rc::downgrade(&v));
                v
            }
        },
    }
}

impl Claim {
    fn with(available: &[Value; N_SLOTS]) -> Self {
        Claim {
            available: *available,
            claimed: *available,
        }
    }

    fn new() -> Self {
        Self::with(&[0; N_SLOTS])
    }
}

impl Acct {
    /// Create a new accounting system.
    ///
    /// All accounting systems are fully independent of each other, and this
    /// object serves as root context for a given accounting system.
    pub fn new(maxima: &[Value; N_SLOTS]) -> rc::Rc<Acct> {
        rc::Rc::new(Self {
            inner: cell::RefCell::new(
                AcctInner {
                    users: btree_map::BTreeMap::new(),
                    maxima: *maxima,
                },
            ),
        })
    }

    /// Get a user object for a given user ID.
    ///
    /// Query the accounting system for the user object of the given user ID.
    /// This will always return an existing user object, if there is one.
    /// Otherwise, it will create a new one.
    ///
    /// It is never possible to have two [`User`] objects with the same user ID
    /// but assigned to the same [`Acct`] object. This lookup function ensures
    /// that user objects are always shared.
    pub fn get_user(self: &rc::Rc<Acct>, id: Id) -> rc::Rc<User> {
        let mut s_borrow = self.inner.borrow_mut();
        let s = &mut *s_borrow;

        // Borrow early, so Rust can properly detect that it is a borrow on
        // a distinct field than `s.users`.
        let s_maxima = &s.maxima;

        // Find the user, or create a new one.
        find_and_upgrade_or_insert_with(
            &mut s.users,
            &id,
            || User::new(self, id, s_maxima),
        )
    }
}

impl UserInner {
    fn quotas_len(&self) -> Value {
        assert!(size_of::<Value>() >= size_of::<usize>());

        convert::TryFrom::try_from(
            self.quotas.len()
        ).unwrap()
    }
}

impl User {
    fn new(
        acct: &rc::Rc<Acct>,
        id: Id,
        maxima: &[Value; N_SLOTS],
    ) -> rc::Rc<User> {
        rc::Rc::new(Self {
            acct: acct.clone(),
            id: id,
            inner: cell::RefCell::new(
                UserInner {
                    quotas: btree_map::BTreeMap::new(),
                    maxima: *maxima,
                    claim: Claim::with(maxima),
                },
            ),
        })
    }

    fn get_quota(self: &rc::Rc<User>, id: Id) -> rc::Rc<Quota> {
        let mut s = self.inner.borrow_mut();

        // Find the quota, or create a new one.
        find_and_upgrade_or_insert_with(
            &mut s.quotas,
            &id,
            || Quota::new(self, id),
        )
    }

    /// Return the configured resource maxima of this user.
    pub fn maxima(&self) -> [Value; N_SLOTS] {
        self.inner.borrow().maxima
    }

    /// Charge resources on this user with the given actor.
    pub fn charge(
        self: &rc::Rc<User>,
        claimant: &rc::Rc<Actor>,
        amount: &[Value; N_SLOTS],
    ) -> Option<Charge> {
        // Resolve all the Rc+RefCell wrappers and pin them for access.
        let quota = self.get_quota(claimant.user.id);
        let trace = quota.get_trace(&rc::Rc::downgrade(claimant));
        let quota_inner = &mut *quota.inner.borrow_mut();
        let trace_inner = &mut *trace.inner.borrow_mut();
        let self_inner = &mut *self.inner.borrow_mut();

        // Check whether we cross boundaries.
        let cross_trace = true;
        let cross_user = quota.cross_user();

        // Get mutable references to all 3 involved claim objects, so
        // we can check the quota on them and eventually apply the charge.
        let n_users = self_inner.quotas_len();
        let n_actors = quota_inner.traces_len();
        let claim_user = &mut self_inner.claim;
        let claim_quota = &mut quota_inner.claim;
        let claim_trace = &mut trace_inner.claim;

        // Remember the charge amount for each level / claim-object.
        let mut reqs = [[0; 3]; N_SLOTS];

        // First check the quota on each slot independently, but apply nothing.
        for (slot, req) in reqs.iter_mut().enumerate() {
            let mut minimum;

            req[0] = amount[slot];

            // Direct allocation
            //
            // We start the allocation request on the trace object, and work
            // our way upwards for as long as the request was not fulfilled.
            //
            // A trace object is a leaf node in the allocation tree, and as
            // such cannot have any overallocated resources. Verify this! Then
            // delegate the request to the next level.

            assert_eq!(claim_trace.available[slot], 0);
            req[1] = req[0];

            // Trace allocation
            //
            // Since the trace object cannot serve the request, we delegate
            // the allocation and request more resources for this trace object
            // from the user. This uses a very lenient allocator, since no user
            // boundaries are crossed, but we merely share resources across
            // actors of the same user.
            //
            // We first calculate how big the reserve of the user has to be
            // to serve the request, and then check whether the user already
            // has enough resources available. If not, we delegate the
            // allocation request to the next level.
            //
            // If trace boundaries are not crossed, we grant full access to
            // all resources.

            minimum = if cross_trace {
                quota_reserve(
                    allocator_exponential,
                    n_actors,
                    claim_trace.claimed[slot],
                    req[1],
                )?
            } else {
                req[1]
            };

            if claim_quota.available[slot] >= minimum {
                continue;
            }

            req[2] = minimum - claim_quota.available[slot];

            // User allocation
            //
            // The reserve of the user was not big enough to serve the request,
            // so we have to request more resources for this user. If this
            // crosses user-boundaries, we have to ensure that a strong
            // allocator is used. But if this does not cross user-boundaries,
            // we grant full access to all resources of the user.

            minimum = if cross_user {
                quota_reserve(
                    allocator_quasilinear,
                    n_users,
                    claim_quota.claimed[slot],
                    req[2],
                )?
            } else {
                req[2]
            };

            if claim_user.available[slot] >= minimum {
                continue;
            }

            // Root allocation
            //
            // The resources of the user were exhausted. We do not support
            // further propagation, but only provide per-user limits. Hence, we
            // have to fail the request.

            return None;
        }

        // With all quotas checked, apply the charge to each slot.
        for (slot, req) in reqs.iter().enumerate() {
            claim_user.available[slot] -= req[2];
            claim_quota.claimed[slot] += req[2];
            claim_quota.available[slot] += req[2];

            claim_quota.available[slot] -= req[1];
            claim_trace.claimed[slot] += req[1];
            claim_trace.available[slot] += req[1];

            claim_trace.available[slot] -= req[0];
        }

        Some(Charge::with(trace.clone(), amount))
    }
}

impl core::ops::Drop for User {
    fn drop(&mut self) {
        // Ensure the weak-ref is dropped from the user map, so it can be
        // properly deallocated.
        self.acct.inner.borrow_mut()
            .users.remove(&self.id);
    }
}

impl Actor {
    /// Create a new actor assigned to the given user.
    ///
    /// Any amount of actors can be create for a given user, and they can be
    /// shared between different operations, if desired. Actors always operate
    /// on behalf of the user they were created for. As such, actors of
    /// differnt users never share any quota. Additionally, multiple actors
    /// assigned to the same user will be protected via a second-level quota.
    ///
    /// Long story short: Resource use of each actor can be safely traced and
    /// is tracked by the resource accounting.
    pub fn with(
        user: &rc::Rc<User>,
    ) -> rc::Rc<Actor> {
        rc::Rc::new(Self {
            user: user.clone(),
        })
    }

    pub fn user(&self) -> &rc::Rc<User> {
        &self.user
    }

    /// Charge resources on the user of this actor with the given claimant
    /// actor.
    pub fn charge(
        self: &rc::Rc<Actor>,
        claimant: &rc::Rc<Actor>,
        amount: &[Value; N_SLOTS],
    ) -> Option<Charge> {
        self.user.charge(
            claimant,
            amount,
        )
    }
}

impl QuotaInner {
    fn traces_len(&self) -> Value {
        assert!(size_of::<Value>() >= size_of::<usize>());

        convert::TryFrom::try_from(
            self.traces.len()
        ).unwrap()
    }
}

impl Quota {
    fn new(
        user: &rc::Rc<User>,
        id: Id,
    ) -> rc::Rc<Quota> {
        rc::Rc::new(Self {
            user: user.clone(),
            id: id,
            inner: cell::RefCell::new(
                QuotaInner {
                    traces: btree_map::BTreeMap::new(),
                    claim: Claim::new(),
                },
            ),
        })
    }

    fn cross_user(&self) -> bool {
        self.id != self.user.id
    }

    fn get_trace(
        self: &rc::Rc<Quota>,
        actor: &rc::Weak<Actor>,
    ) -> rc::Rc<Trace> {
        let mut s = self.inner.borrow_mut();

        // Find the trace, or create a new one.
        find_and_upgrade_or_insert_with(
            &mut s.traces,
            &rc::Weak::as_ptr(actor),
            || Trace::new(self, actor),
        )
    }
}

impl core::ops::Drop for Quota {
    fn drop(&mut self) {
        // Ensure the weak-ref is dropped from the quota map, so it can be
        // properly deallocated.
        self.user.inner.borrow_mut()
            .quotas.remove(&self.id);
    }
}

impl Trace {
    fn new(
        quota: &rc::Rc<Quota>,
        actor: &rc::Weak<Actor>,
    ) -> rc::Rc<Trace> {
        rc::Rc::new(Self {
            quota: quota.clone(),
            actor: actor.as_ptr(),
            inner: cell::RefCell::new(
                TraceInner {
                    claim: Claim::new(),
                },
            ),
        })
    }

    fn discharge(
        self: &rc::Rc<Trace>,
        amount: &[Value; N_SLOTS],
    ) {
        let trace_inner = &mut *self.inner.borrow_mut();
        let quota_inner = &mut *self.quota.inner.borrow_mut();
        let user_inner = &mut *self.quota.user.inner.borrow_mut();

        // Get mutable references to all 3 involved claim objects.
        let n_actors = quota_inner.traces_len();
        let claim_user = &mut user_inner.claim;
        let claim_quota = &mut quota_inner.claim;
        let claim_trace = &mut trace_inner.claim;

        for (slot, amount_slot) in amount.iter().enumerate() {
            let mut n;

            // Release the amount on the trace-object and make it available as
            // cached resources. We do this for completeness reasons, but we
            // immediately release the resources to the next layer in full.

            n = *amount_slot;

            claim_trace.available[slot] += n;

            // Release all unused resources on the trace object and grant them
            // back to the user. We do not want to cache any resources on the
            // trace object, yet, but always ensure everything is properly
            // returned to the lower levels.

            n = claim_trace.available[slot];

            claim_trace.available[slot] -= n;
            claim_trace.claimed[slot] -= n;
            claim_quota.available[slot] += n;

            // When returning resources to the reserve of the user, we check
            // how big the reserve needs to be, so we can shrink it if possible
            // and ensure unneeded resources are always released to lower
            // levels.
            //
            // To figure out how big the reserve needs to be, we simply
            // calculate the average amount that a trace object has claimed,
            // and then pretend to allocate that amount. This will calculate
            // a suitable resource, which we then shrink to. This also ensures
            // that if the average is 0, the minimum reserve will also be 0.

            let claimed = claim_quota.claimed[slot];
            let available = claim_quota.available[slot];

            let average = claimed
                .checked_sub(available)
                .unwrap()
                .checked_div(n_actors)
                .unwrap();

            let minimum = quota_reserve(
                allocator_exponential,
                n_actors,
                average,
                0,
            ).unwrap_or(Value::MAX);

            if minimum < claim_quota.available[slot] {
                n = claim_quota.available[slot] - minimum;
                claim_quota.available[slot] -= n;
                claim_quota.claimed[slot] -= n;
                claim_user.available[slot] += n;
            }
        }
    }
}

impl core::ops::Drop for Trace {
    fn drop(&mut self) {
        // Ensure the weak-ref is dropped from the trace map, so it can be
        // properly deallocated.
        self.quota.inner.borrow_mut()
            .traces.remove(&self.actor);
    }
}

impl Charge {
    fn with(
        trace: rc::Rc<Trace>,
        amount: &[Value; N_SLOTS],
    ) -> Self {
        Self {
            inner: ChargeInner {
                trace: Some(trace),
                amount: *amount,
            },
        }
    }

    /// Re-create a charge from its raw values.
    ///
    /// ## Safety
    ///
    /// This must be called with the values previously acquired via
    /// [`Self::into_raw()`].
    pub unsafe fn from_raw(
        raw: util_acct::AcctCharge,
    ) -> Self {
        Self::with(
            unsafe { rc::Rc::from_raw(raw.trace as _) },
            &raw.amount,
        )
    }

    /// Destructure a charge into its raw values.
    pub fn into_raw(mut self) -> util_acct::AcctCharge {
        let mut this = ChargeInner { trace: None, amount: [0; N_SLOTS] };

        core::mem::swap(&mut self.inner, &mut this);

        util_acct::AcctCharge {
            trace: rc::Rc::into_raw(this.trace.unwrap()) as _,
            amount: this.amount,
        }
    }

    /// Discharge the claimed resources.
    ///
    /// This is equivalent to dropping the object.
    pub fn discharge(self) {
        drop(self)
    }
}

impl core::ops::Drop for Charge {
    fn drop(&mut self) {
        if let Some(ref v) = self.inner.trace {
            v.discharge(&self.inner.amount);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        let acct = Acct::new(&[1024; N_SLOTS]);
        let u0 = acct.get_user(0);
        let u1 = acct.get_user(1);
        let u2 = acct.get_user(2);
        let u0a0 = Actor::with(&u0);
        let u0a1 = Actor::with(&u0);
        let u1a0 = Actor::with(&u1);
        let u1a1 = Actor::with(&u1);
        let u2a0 = Actor::with(&u2);
        let u2a1 = Actor::with(&u2);

        // Perform a self-charge and verify that half of the resources is the
        // maximum that can be requested. Also verify that this grants full
        // access to all user resources (i.e., requests of other users always
        // fail).
        // Then verify that releasing a chunk allows reclaiming the resources.
        {
            let _c0 = u0a0.charge(&u0a0, &[256; N_SLOTS]).unwrap();
            let c1 = u0a0.charge(&u0a0, &[256; N_SLOTS]).unwrap();
            assert!(u0a0.charge(&u0a0, &[1; N_SLOTS]).is_none());
            assert!(u0a0.charge(&u1a0, &[1; N_SLOTS]).is_none());

            drop(c1);
            let _c2 = u0a0.charge(&u0a0, &[256; N_SLOTS]).unwrap();
        }

        // Perform a self-charge with two actors, and verify the first gets
        // half, and the second gets half of that. Also ensure foreign actors
        // cannot claim anything, since this series requires the full resource
        // set of the user.
        {
            let _c0 = u0a0.charge(&u0a0, &[512; N_SLOTS]).unwrap();
            assert!(u0a0.charge(&u0a0, &[1; N_SLOTS]).is_none());
            assert!(u0a0.charge(&u1a0, &[1; N_SLOTS]).is_none());

            let _c1 = u0a0.charge(&u0a1, &[256; N_SLOTS]).unwrap();
            assert!(u0a0.charge(&u0a0, &[1; N_SLOTS]).is_none());
            assert!(u0a0.charge(&u0a1, &[1; N_SLOTS]).is_none());
        }

        // Perform a foreign-charge with two actors of the same UID, and verify
        // that they share the foreign charge (i.e., the second charge is half
        // of the first charge, if both charge to their limit).
        // Then perform a foreign-charge of another two actors of yet another
        // UID. Again, charge to their limit (which must be non-zero, since the
        // quota separates them from the previous charges) and verify it is
        // the expected limit.
        {
            let _c0 = u0a0.charge(&u1a0, &[128; N_SLOTS]).unwrap();
            assert!(u0a0.charge(&u1a0, &[1; N_SLOTS]).is_none());
            let _c1 = u0a0.charge(&u1a1, &[64; N_SLOTS]).unwrap();
            assert!(u0a0.charge(&u1a0, &[1; N_SLOTS]).is_none());
            let _c2 = u0a0.charge(&u2a0, &[42; N_SLOTS]).unwrap();
            assert!(u0a0.charge(&u2a0, &[1; N_SLOTS]).is_none());
            let _c3 = u0a0.charge(&u2a1, &[21; N_SLOTS]).unwrap();
            assert!(u0a0.charge(&u2a1, &[1; N_SLOTS]).is_none());
        }
    }
}
