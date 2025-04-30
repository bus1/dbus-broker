//! # C-Rust Bridge
//!
//! This module implements a C API for the rust library bundles with the
//! bus broker.

extern crate alloc;
extern crate core;

// Helper macro to ensure two expressions have the same type.
//
// This macro relies on if/else expressions to require both blocks
// to have the same type. Otherwise, this will yield to compile errors.
macro_rules! type_eq {
    ($a:expr, $b:expr) => {
        const _: () = {
            if true {
                ($a)
            } else {
                ($b)
            };
        };
    };
}

mod acct {
    use alloc::rc;
    use core::{ffi, mem, ptr};
    use rbus::generated::util_acct;
    use rbus::util::acct;

    #[unsafe(export_name = "acct_new")]
    pub unsafe extern "C" fn acct_new(
        acctp: *mut *mut util_acct::Acct,
        maxima_c: *const [util_acct::acct_value_t; acct::N_SLOTS],
    ) -> ffi::c_int {
        type_eq!(acct_new, util_acct::acct_new);

        let maxima = unsafe { &*maxima_c };
        let acct = acct::Acct::new(maxima);

        unsafe { ptr::write(acctp, rc::Rc::into_raw(acct) as _) };
        0
    }

    #[unsafe(export_name = "acct_free")]
    pub unsafe extern "C" fn acct_free(
        acct_c: *mut util_acct::Acct,
    ) -> *mut util_acct::Acct {
        type_eq!(acct_free, util_acct::acct_free);

        let acct: rc::Rc<acct::Acct> = unsafe { rc::Rc::from_raw(acct_c as _) };
        drop(acct);

        ptr::null_mut()
    }

    #[unsafe(export_name = "acct_ref_user")]
    pub unsafe extern "C" fn acct_ref_user(
        acct_c: *mut util_acct::Acct,
        userp: *mut *mut util_acct::AcctUser,
        id_c: util_acct::acct_id_t,
    ) -> ffi::c_int {
        type_eq!(acct_ref_user, util_acct::acct_ref_user);

        let acct: rc::Rc<acct::Acct> = unsafe { rc::Rc::from_raw(acct_c as _) };
        let user = acct.get_user(id_c);

        unsafe { ptr::write(userp, rc::Rc::into_raw(user) as _) };
        mem::forget(acct);
        0
    }

    #[unsafe(export_name = "acct_user_ref")]
    pub unsafe extern "C" fn acct_user_ref(
        user_c: *mut util_acct::AcctUser,
    ) -> *mut util_acct::AcctUser {
        type_eq!(acct_user_ref, util_acct::acct_user_ref);

        let user: rc::Rc<acct::User> = unsafe { rc::Rc::from_raw(user_c as _) };
        mem::forget(user.clone());

        rc::Rc::into_raw(user) as _
    }

    #[unsafe(export_name = "acct_user_unref")]
    pub unsafe extern "C" fn acct_user_unref(
        user_c: *mut util_acct::AcctUser,
    ) -> *mut util_acct::AcctUser {
        type_eq!(acct_user_unref, util_acct::acct_user_unref);

        let user: rc::Rc<acct::User> = unsafe { rc::Rc::from_raw(user_c as _) };
        drop(user);

        ptr::null_mut()
    }

    #[unsafe(export_name = "acct_user_new_actor")]
    pub unsafe extern "C" fn acct_user_new_actor(
        user_c: *mut util_acct::AcctUser,
        actorp: *mut *mut util_acct::AcctActor,
    ) -> ffi::c_int {
        type_eq!(acct_user_new_actor, util_acct::acct_user_new_actor);

        let user: rc::Rc<acct::User> = unsafe { rc::Rc::from_raw(user_c as _) };
        let actor = acct::Actor::with(&user);

        unsafe { ptr::write(actorp, rc::Rc::into_raw(actor) as _) };
        mem::forget(user);
        0
    }

    #[unsafe(export_name = "acct_user_charge")]
    pub unsafe extern "C" fn acct_user_charge(
        user_c: *mut util_acct::AcctUser,
        charge_raw_c: *mut util_acct::AcctCharge,
        claimant_c: *mut util_acct::AcctActor,
        amount_c: *const [util_acct::acct_value_t; acct::N_SLOTS],
    ) -> ffi::c_int {
        type_eq!(acct_user_charge, util_acct::acct_user_charge);

        let user: rc::Rc<acct::User> = unsafe { rc::Rc::from_raw(user_c as _) };
        let claimant: rc::Rc<acct::Actor> = unsafe { rc::Rc::from_raw(claimant_c as _) };
        let amount = unsafe { &*amount_c };

        let Some(charge) = user.charge(&claimant, amount) else {
            return util_acct::ACCT_E_QUOTA;
        };

        let charge_raw = unsafe { &mut *charge_raw_c };
        if !charge_raw.trace.is_null() {
            let charge_prev = unsafe { acct::Charge::from_raw(*charge_raw) };
            charge_prev.discharge();
        }

        ptr::write(charge_raw_c, charge.into_raw());

        mem::forget(claimant);
        mem::forget(user);
        0
    }

    #[unsafe(export_name = "acct_actor_ref")]
    pub unsafe extern "C" fn acct_actor_ref(
        actor_c: *mut util_acct::AcctActor,
    ) -> *mut util_acct::AcctActor {
        type_eq!(acct_actor_ref, util_acct::acct_actor_ref);

        let actor: rc::Rc<acct::Actor> = unsafe { rc::Rc::from_raw(actor_c as _) };
        mem::forget(actor.clone());

        rc::Rc::into_raw(actor) as _
    }

    #[unsafe(export_name = "acct_actor_unref")]
    pub unsafe extern "C" fn acct_actor_unref(
        actor_c: *mut util_acct::AcctActor,
    ) -> *mut util_acct::AcctActor {
        type_eq!(acct_actor_unref, util_acct::acct_actor_unref);

        let actor: rc::Rc<acct::Actor> = unsafe { rc::Rc::from_raw(actor_c as _) };
        drop(actor);

        ptr::null_mut()
    }

    #[unsafe(export_name = "acct_actor_charge")]
    pub unsafe extern "C" fn acct_actor_charge(
        actor_c: *mut util_acct::AcctActor,
        charge: *mut util_acct::AcctCharge,
        claimant: *mut util_acct::AcctActor,
        amount: *const [util_acct::acct_value_t; acct::N_SLOTS],
    ) -> ffi::c_int {
        type_eq!(acct_actor_charge, util_acct::acct_actor_charge);

        let actor: rc::Rc<acct::Actor> = unsafe { rc::Rc::from_raw(actor_c as _) };
        let user_raw = rc::Rc::as_ptr(actor.user());

        let r = acct_user_charge(
            user_raw as _,
            charge,
            claimant,
            amount,
        );

        mem::forget(actor);
        r
    }
}
