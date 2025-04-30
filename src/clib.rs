//! # C-Rust Bridge
//!
//! XXX

mod acct {
    use rbus::generated::util_acct;
    use rbus::util::acct;

    #[unsafe(export_name = "acct_new")]
    pub extern "C" fn acct_new(
        acctp: *mut *mut util_acct::Acct,
        maxima: *const [util_acct::acct_value_t; acct::N_SLOTS],
    ) -> ::core::ffi::c_int {
        unsafe {
            let acct = acct::Acct::new(&*maxima);
            *acctp = std::rc::Rc::into_raw(acct) as *mut _;
        }
        0
    }

    #[unsafe(export_name = "acct_free")]
    pub extern "C" fn acct_free(
        acct_c: *mut util_acct::Acct,
    ) -> *mut util_acct::Acct {
        let _ = unsafe { std::rc::Rc::from_raw(acct_c) };
        core::ptr::null_mut()
    }

    /*
    #[unsafe(export_name = "acct_user_ref")]
    pub extern "C" fn user_ref(
        user: *mut util_acct::AcctUser,
    ) -> *mut util_acct::AcctUser {
        let u = unsafe { rc::Rc::from_raw(user as *mut User) };
        core::mem::forget(u.clone());
        user
    }
    */
}
