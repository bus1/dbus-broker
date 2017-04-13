/*
 * Bus Manager
 */

#include <c-macro.h>
#include <stdlib.h>
#include "main.h"
#include "manager.h"

struct Manager {
        int unused;
};

int manager_new(Manager **managerp) {
        _c_cleanup_(manager_freep) Manager *manager = NULL;

        manager = calloc(1, sizeof(*manager));
        if (!manager)
                return -ENOMEM;

        *managerp = manager;
        manager = NULL;
        return 0;
}

Manager *manager_free(Manager *manager) {
        if (!manager)
                return NULL;

        free(manager);

        return NULL;
}

int manager_run(Manager *manager) {
        return 0;
}
