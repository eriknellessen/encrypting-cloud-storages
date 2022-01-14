#include <string.h>
#include <criterion/criterion.h>
#include <criterion/new/assert.h>
#include "../data_operations.h"

Test(data_operations_test_suite, local_string_concatenation_test) {
    LOCAL_STR_CAT("foo", "bar", concatenated_string)
    cr_assert(eq(str, concatenated_string, "foobar"), "Did not concatenate strings as expected!");
}
