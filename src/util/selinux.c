/*
 * BusSELinux Helpers
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#include <stdlib.h>
#include "util/error.h"
#include "util/selinux.h"

struct BusSELinux {
        struct avc_entry_ref aeref;
        security_id_t default_sid;
        CRBTree names;
};

struct BusSELinuxName {
        security_id_t sid;
        CRBNode rb;
        char name[];
};

typedef struct BusSELinuxName BusSELinuxName;

#define BUS_SELINUX_SID_FROM_BUS(sid)   ((security_id_t) (sid))

#define BUS_SELINUX_CLASS_DBUS          (1UL)

#define BUS_SELINUX_PERMISSION_OWN      (1UL)
#define BUS_SELINUX_PERMISSION_SEND     (2UL)

static struct security_class_mapping permissions_map[] = {
  { "dbus", { "acquire_svc", "send_msg", NULL } },
  { NULL }
};

bool bus_selinux_is_enabled(void) {
        return is_selinux_enabled();
}

int bus_selinux_sid_init(BusSELinuxSID **sidp, const char *seclabel) {
        security_id_t sid;
        int r;

        if (!is_selinux_enabled())
                return 0;

        r = avc_context_to_sid(seclabel, &sid);
        if (r < 0)
                return error_origin(-errno);

        *sidp = (BusSELinuxSID *)sid;

        return 0;
}

static BusSELinuxName *bus_selinux_name_free(BusSELinuxName *name) {
        if (!name)
                return NULL;

        assert(!c_rbnode_is_linked(&name->rb));

        free(name);

        return NULL;
}

C_DEFINE_CLEANUP(BusSELinuxName *, bus_selinux_name_free);

static int bus_selinux_name_new(const char *name, const char *seclabel, CRBTree *tree, CRBNode *parent, CRBNode **slot) {
        _c_cleanup_(bus_selinux_name_freep) BusSELinuxName *selinux_name = NULL;
        size_t n_name = strlen(name) + 1;
        int r;

        selinux_name = malloc(sizeof(*selinux_name) + n_name);
        if (!selinux_name)
                return error_origin(-ENOMEM);
        selinux_name->rb = (CRBNode)C_RBNODE_INIT(selinux_name->rb);
        memcpy(selinux_name->name, name, n_name);

        r = avc_context_to_sid(seclabel, &selinux_name->sid);
        if (r < 0)
                return error_origin(-errno);

        c_rbtree_add(tree, parent, slot, &selinux_name->rb);
        selinux_name = NULL;

        return 0;
}

int bus_selinux_new(BusSELinux **selinuxp, const char *seclabel) {
        _c_cleanup_(bus_selinux_freep) BusSELinux *selinux = NULL;
        int r;

        selinux = malloc(sizeof(*selinux));
        if (!selinux)
                return error_origin(-ENOMEM);

        avc_entry_ref_init(&selinux->aeref);
        selinux->names = (CRBTree)C_RBTREE_INIT;

        if (is_selinux_enabled()) {
                r = selinux_set_mapping(permissions_map);
                if (r < 0)
                        return error_origin(-errno);

                /* Note: this keeps global state. */
                r = avc_open(NULL, 0);
                if (r)
                        return error_origin(-errno);

                /* XXX: set logging callbacks */

                r = avc_context_to_sid(seclabel, &selinux->default_sid);
                if (r < 0)
                        return error_origin(-errno);
        }

        *selinuxp = selinux;
        selinux = NULL;
        return 0;
}

BusSELinux *bus_selinux_free(BusSELinux *selinux) {
        BusSELinuxName *name, *name_safe;

        if (!selinux)
                return NULL;

        c_rbtree_for_each_entry_unlink(name, name_safe, &selinux->names, rb)
                bus_selinux_name_free(name);

        avc_destroy();
        free(selinux);

        return NULL;
}

static int name_compare(CRBTree *t, void *k, CRBNode *rb) {
        const char *name = (const char *)k;
        BusSELinuxName *selinux_name = c_container_of(rb, BusSELinuxName, rb);

        return strcmp(name, selinux_name->name);
}

int bus_selinux_add_name(BusSELinux *selinux, const char *name, const char *seclabel) {
        CRBNode *parent, **slot;
        int r;

        if (!is_selinux_enabled())
                return 0;

        slot = c_rbtree_find_slot(&selinux->names, name_compare, name, &parent);
        if (slot) {
                r = bus_selinux_name_new(name, seclabel, &selinux->names, parent, slot);
                if (r)
                        return error_trace(r);
        } else {
                BusSELinuxName *selinux_name;

                selinux_name = c_container_of(parent, BusSELinuxName, rb);

                r = avc_context_to_sid(seclabel, &selinux_name->sid);
                if (r < 0)
                        return error_origin(-errno);
        }

        return 0;
}

int bus_selinux_check_own(BusSELinux *selinux,
                          BusSELinuxSID *owner_sid,
                          const char *name) {
        BusSELinuxName *selinux_name;
        security_id_t name_sid;
        int r;

        if (!is_selinux_enabled())
                return 0;

        selinux_name = c_rbtree_find_entry(&selinux->names, name_compare, name, BusSELinuxName, rb);
        if (selinux_name)
                name_sid = selinux_name->sid;
        else
                name_sid = selinux->default_sid;

        r = avc_has_perm_noaudit(BUS_SELINUX_SID_FROM_BUS(owner_sid),
                                 name_sid,
                                 BUS_SELINUX_CLASS_DBUS,
                                 BUS_SELINUX_PERMISSION_OWN,
                                 &selinux->aeref, NULL);
        if (r < 0) {
                if (errno == EACCES)
                        return SELINUX_E_DENIED;

                return error_origin(-errno);
        }

        return 0;
}

int bus_selinux_check_send(BusSELinux *selinux,
                           BusSELinuxSID *sender_sid,
                           BusSELinuxSID *receiver_sid) {
        int r;

        if (!is_selinux_enabled())
                return 0;

        r = avc_has_perm_noaudit(BUS_SELINUX_SID_FROM_BUS(sender_sid),
                                 BUS_SELINUX_SID_FROM_BUS(receiver_sid),
                                 BUS_SELINUX_CLASS_DBUS,
                                 BUS_SELINUX_PERMISSION_SEND,
                                 &selinux->aeref, NULL);
        if (r < 0) {
                if (errno == EACCES)
                        return SELINUX_E_DENIED;

                return error_origin(-errno);
        }

        return 0;
}
