#pragma once

/*
 * Resource Accounting
 */

#include <c-stdaux.h>
#include <stdlib.h>

typedef uint32_t acct_id_t;
typedef uint64_t acct_value_t;

typedef struct Acct Acct;
typedef struct AcctActor AcctActor;
typedef struct AcctCharge AcctCharge;
typedef struct AcctUser AcctUser;

enum: int {
        _ACCT_E_SUCCESS,

        ACCT_E_QUOTA,
};

enum: size_t {
        ACCT_SLOT_BYTES,
        ACCT_SLOT_FDS,
        ACCT_SLOT_MATCHES,
        ACCT_SLOT_OBJECTS,
        _ACCT_SLOT_N,
};

/* charge */

struct AcctCharge {
        void *trace;
        acct_value_t amount[_ACCT_SLOT_N];
};

#define ACCT_CHARGE_INIT {}

void acct_charge_init(AcctCharge *charge);
void acct_charge_deinit(AcctCharge *charge);

/* acct */

int acct_new(Acct **acctp, const acct_value_t (*maxima)[_ACCT_SLOT_N]);
Acct *acct_free(Acct *acct);

int acct_ref_user(Acct *acct, AcctUser **userp, acct_id_t id);

/* user */

AcctUser *acct_user_ref(AcctUser *user);
AcctUser *acct_user_unref(AcctUser *user);

int acct_user_new_actor(AcctUser *user, AcctActor **actorp);
int acct_user_charge(
        AcctUser *user,
        AcctCharge *charge,
        AcctActor *claimant,
        const acct_value_t (*const amount)[_ACCT_SLOT_N]
);

/* actor */

AcctActor *acct_actor_ref(AcctActor *actor);
AcctActor *acct_actor_unref(AcctActor *actor);

int acct_actor_charge(
        AcctActor *actor,
        AcctCharge *charge,
        AcctActor *claimant,
        const acct_value_t (*const amount)[_ACCT_SLOT_N]
);
