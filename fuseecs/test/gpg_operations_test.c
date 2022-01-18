#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../gpg_operations.h"

int __real_access(const char *pathname, int how);
int __wrap_access(const char *pathname, int how) {
    if (strlen(pathname) > 5 && !strcmp(pathname + strlen(pathname) - 5, ".gcda")) {
        return __real_access(pathname, how);
    }

    check_expected(pathname);
    return mock_type(int);
}

static void test_directory_contains_authentic_file(void **state) {
    expect_string(__wrap_access, pathname, "/foo/bar.txt.gpg");
    will_return(__wrap_access, 1);
    
    char *encrypted_directory = "/foo/";
    char *file_name = "bar.txt";
    int return_value = directory_contains_authentic_file(encrypted_directory, file_name);
    assert_int_equal(return_value, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_directory_contains_authentic_file),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
