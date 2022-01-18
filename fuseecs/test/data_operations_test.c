#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../data_operations.h"

static void test_local_string_concatenation(void **state) {
    LOCAL_STR_CAT("foo", "bar", concatenated_string)
    assert_string_equal(concatenated_string, "foobar");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_local_string_concatenation),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
