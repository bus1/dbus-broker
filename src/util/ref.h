#pragma once

/*
 * Atomic Reference Counter
 *
 * This implements an atomic reference counter. That is, references can be
 * acquired and released from multiple threads in parallel.
 *
 * To use CRef, an object needs a member of type `_Atomic unsigned long', which
 * counts the references. All functions here take it as first argument and only
 * operate on this one field.
 */

#include <assert.h>
#include <c-stdaux.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdnoreturn.h>

typedef void (*RefFn) (_Atomic unsigned long *ref, void *userdata);

/**
 * REF_INIT - initialize static reference counter
 *
 * This provides a static initializer for a reference counter. It is meant to
 * be used as assignment for variables or member fields.
 */
#define REF_INIT ATOMIC_VAR_INIT(1UL)

/**
 * ref_add() - acquire references
 * @ref:                reference counter to operate on, or NULL
 * @n:                  number of references to acquire
 *
 * Acquire @n references to the reference counter @ref. The caller must
 * guarantee that they already own a reference to @n. Furthermore, the caller
 * must ensure that this cannot overflow 'unsigned long' (usually it is enough
 * to ensure that a reference is associated with some allocated object).
 *
 * If @ref is NULL, this is a no-op. @n must not be 0.
 *
 * Return: @ref is returned.
 */
static inline _Atomic unsigned long *ref_add(_Atomic unsigned long *ref, unsigned long n) {
        unsigned long n_refs;

        c_assert(n > 0);

        if (ref) {
                /*
                 * Acquire references but do not place any barriers. Nobody
                 * should place decisions based on this operations, ever! So no
                 * need to order it.
                 */
                n_refs = atomic_fetch_add_explicit(ref, n, memory_order_relaxed);
                c_assert(n_refs > 0);
        }

        return ref;
}

/**
 * ref_add_unless_zero() - acquire references if possible
 * @ref:                reference counter to operate on, or NULL
 * @n:                  number of references to acquire
 *
 * Acquire @n references to the reference counter @ref, if, and only if, it has
 * not already dropped to 0. In case of success, this has the same effect as
 * ref_add(). In case of failure, this will return NULL without acquiring any
 * reference. The caller must check the return value of this function.
 *
 * This function does not give any memory ordering guarantees. Just like
 * ref_add(), no decision should be placed based on the fact that a reference
 * has been acquired. That is, even if this returns NULL, the caller must not
 * try to deduce the state of the surrounding object. Furthermore, the caller
 * must provide sufficient synchronization on the pointer to the object. This
 * function just makes sure to never acquire references to possibly unlocked
 * objects that have already been released. Any further synchronization is up
 * to the caller.
 *
 * If @ref is NULL, this is a no-op. @n must not be 0.
 *
 * Return: @ref is returned on success, otherwise NULL is returned.
 */
static inline _Atomic unsigned long *ref_add_unless_zero(_Atomic unsigned long *ref, unsigned long n) {
        unsigned long n_refs;

        c_assert(n > 0);

        if (ref) {
                /*
                 * Try replacing *ref with (*ref + n). This requires us to
                 * fetch the value and loop on cmpxchg. On failure, bail out
                 * with NULL. Otherwise, retry until we completed the task.
                 * Note that we do not provide barriers. We expect the caller
                 * to synchronize via the actual pointer of the object. If this
                 * function fails, the caller should not use this information
                 * to deduce the state of the object. It must rely on external
                 * synchronization, if that is required.
                 */
                n_refs = atomic_load_explicit(ref, memory_order_relaxed);
                do {
                        if (n_refs == 0)
                                return NULL;
                } while (!atomic_compare_exchange_weak_explicit(ref, &n_refs, n_refs + n,
                                                                memory_order_relaxed,
                                                                memory_order_relaxed));
        }

        return ref;
}

/**
 * ref_inc() - acquire reference
 * @ref:                reference counter to operate on, or NULL
 *
 * This acquires a single reference to @ref. See ref_add() for details. The
 * caller must guarantee that it already owns a reference to @ref.
 *
 * If @ref is NULL, this is a no-op.
 *
 * Return: @ref is returned.
 */
static inline _Atomic unsigned long *ref_inc(_Atomic unsigned long *ref) {
        return ref_add(ref, 1UL);
}

/**
 * ref_inc_unless_zero() - acquire reference if possible
 * @ref:                reference counter to operate on, or NULL
 *
 * Acquire a single reference to @ref, if the reference counter has not already
 * dropped to zero. See ref_add_unless_zero() for details.
 *
 * If @ref is NULL, this is a no-op.
 *
 * Return: @ref is returned on success, otherwise NULL is returned.
 */
static inline _Atomic unsigned long *ref_inc_unless_zero(_Atomic unsigned long *ref) {
        return ref_add_unless_zero(ref, 1UL);
}

/**
 * ref_unreachable() - convenience callback
 * @ref:                reference counter to release
 * @userdata:           userdata provided by caller
 *
 * This is a convenience callback to pass to ref_sub() and friends, if, and
 * only if, you are sure that your call will not cause the reference counter to
 * drop to 0. This release callback will abort the application if it is
 * actually called.
 */
noreturn static inline void ref_unreachable(_Atomic unsigned long *ref, void *userdata) {
        c_assert(0);
        abort();
}

/**
 * ref_sub() - release references
 * @ref:                reference counter to operate on, or NULL
 * @n:                  number of references to release
 * @func:               release function, or NULL
 * @userdata:           userdata to pass to release function
 *
 * Release @n references to the reference counter @ref. The caller must ensure
 * that it actually owns @n references when calling this. If this causes the
 * counter to drop to 0, then @func will be invoked (if non-NULL), with @ref
 * and @userdata passed to it. Otherwise, @func is not invoked and the call
 * simply returns to the caller after dropping @n references.
 *
 * This function provides sufficient read/write barriers regarding any
 * modifications of the object associated with @ref. That is, when an object is
 * actually released (i.e., @func is called), any prior writes of any thread
 * that were done while holding a reference, are guaranteed to be visible to
 * the release thread.
 *
 * If @ref is NULL, this is a no-op. @n must not be 0.
 *
 * Return: NULL is returned.
 */
static inline _Atomic unsigned long *ref_sub(_Atomic unsigned long *ref, unsigned long n, RefFn func, void *userdata) {
        unsigned long n_refs;

        if (ref) {
                /*
                 * Make sure to order all our stores to the object before
                 * releasing the reference. We must guarantee that a racing
                 * unref operation will see our stores before they release the
                 * object. We could use memory_order_acq_rel, but we rather
                 * perform the acquire-barrier only in the release-path, since
                 * it is only needed there.
                 */
                n_refs = atomic_fetch_sub_explicit(ref, n, memory_order_release);
                c_assert(n_refs >= n);
                if (n_refs == n) {
                        atomic_thread_fence(memory_order_acquire);
                        if (func)
                                func(ref, userdata);
                }
        }

        return NULL;
}

/**
 * ref_dec() - release a single reference
 * @ref:                reference counter to operate on, or NULL
 * @func:               release function, or NULL
 * @userdata:           userdata to pass to release function
 *
 * This releases a single reference to @ref. See ref_sub() for details.
 *
 * If @ref is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline _Atomic unsigned long *ref_dec(_Atomic unsigned long *ref, RefFn func, void *userdata) {
        return ref_sub(ref, 1UL, func, userdata);
}
