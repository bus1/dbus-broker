/*
 * D-Bus Session Initiator Main Entry
 */

#include <inttypes.h>

extern int32_t dbrk_session_main(int32_t argc, uint8_t **argv);

int main(int argc, char **argv) {
        return dbrk_session_main(argc, (uint8_t **)argv);
}
