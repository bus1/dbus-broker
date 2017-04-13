#pragma once

/*
 * Bus Manager
 */

#include <c-macro.h>
#include <stdlib.h>

typedef struct Manager Manager;

int manager_new(Manager **managerp);
Manager *manager_free(Manager *manager);

int manager_run(Manager *manager);

C_DEFINE_CLEANUP(Manager *, manager_free);
