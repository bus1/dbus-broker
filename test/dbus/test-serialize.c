/*
 * Serialize and Deserialize Tests
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/serialize.h"
#include "util/string.h"

static void test_basic() {
        FILE *f = NULL;
        _c_cleanup_(c_freep) char *buf = malloc(LINE_LENGTH_MAX);
        int mem_fd;

        mem_fd = state_file_init(&f);
        c_assert(mem_fd > 0);

        c_assert(!serialize_basic(f, "test_u", "%u", 1234));
        c_assert(!serialize_basic(f, "test_d", "%d", -1234));
        c_assert(!serialize_basic(f, "test_s", "%s", "test"));
        c_assert(!serialize_basic(f, "test_uds", "%u;%d;%s", 1234, -1234, "test"));

        fseeko(f, 0, SEEK_SET);

        if (fgets(buf, LINE_LENGTH_MAX, f) != NULL)
                c_assert(!strcmp(buf, "test_u=1234\n"));
        if (fgets(buf, LINE_LENGTH_MAX, f) != NULL)
                c_assert(!strcmp(buf, "test_d=-1234\n"));
        if (fgets(buf, LINE_LENGTH_MAX, f) != NULL)
                c_assert(!strcmp(buf, "test_s=test\n"));
        if (fgets(buf, LINE_LENGTH_MAX, f) != NULL)
                c_assert(!strcmp(buf, "test_uds=1234;-1234;test\n"));

        c_assert(!fgets(buf, LINE_LENGTH_MAX, f));
}

static void test_extract_world_inlist() {
        char *list1 = ";;a;b;;c;;;";
        char *list2 = "a;;bb;ccc;;;";
        char *res1[] = {"a", "b", "c"};
        char *res2[] = {"a", "bb", "ccc"};
        char *res = malloc(10);

        int i = 0;
        while (true) {
                list1 = extract_word_inlist(list1, &res);
                if (!list1)
                        break;
                c_assert(!strcmp(res, res1[i++]));
        }

        i = 0;
        while (true) {
                list2 = extract_word_inlist(list2, &res);
                if (!list2)
                        break;
                c_assert(!strcmp(res, res2[i++]));
        }
}

static void test_extract_list_element() {
        char *list1 = "[{}]";
        char *list2 = "[{a}{b}{c}]";
        char *list3 = "[{a}{{{b}}{}}{c}]";
        char *res2_3[] = {"a", "b", "c"};
        char *res = malloc(10);

        int i = 0;
        while (true) {
                list1 = extract_list_element(list1, &res);
                if (!list1)
                        break;
                c_assert(!res);
        }

        i = 0;
        while (true) {
                list2 = extract_list_element(list2, &res);
                if (!list2)
                        break;
                c_assert(!strcmp(res, res2_3[i++]));
        }

        i = 0;
        while (true) {
                list3 = extract_list_element(list3, &res);
                if (!list3)
                       break;
                c_assert(!strcmp(res, res2_3[i++]));
        }
}

int main(int argc, char **argv) {
        test_basic();
        test_extract_world_inlist();
        test_extract_list_element();
        return 0;
}
