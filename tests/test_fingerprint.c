#include <check.h>

#include "axolotl.h"
#include "curve.h"
#include "fingerprint.h"
#include "test_common.h"

axolotl_context *global_context;

void test_setup()
{
    int result;
    result = axolotl_context_create(&global_context, 0);
    ck_assert_int_eq(result, 0);
    axolotl_context_set_log_function(global_context, test_log);
    setup_test_crypto_provider(global_context);
}

void test_teardown()
{
    axolotl_context_destroy(global_context);
}

START_TEST(test_scannable_fingerprint_serialize)
{
    int result = 0;
    ec_public_key *alice_identity_key = create_test_ec_public_key(global_context);
    ec_public_key *bob_identity_key = create_test_ec_public_key(global_context);
    scannable_fingerprint *alice_scannable = 0;
    scannable_fingerprint *bob_scannable = 0;
    axolotl_buffer *buffer = 0;
    scannable_fingerprint *bob_deserialized = 0;

    result = scannable_fingerprint_create(&alice_scannable, 1,
            "+14152222222", alice_identity_key,
            "+14153333333", bob_identity_key);
    ck_assert_int_eq(result, 0);

    result = scannable_fingerprint_create(&bob_scannable, 1,
            "+14153333333", bob_identity_key,
            "+14152222222", alice_identity_key);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(scannable_fingerprint_compare(alice_scannable, bob_scannable), 1);

    result = scannable_fingerprint_serialize(&buffer, bob_scannable);
    ck_assert_int_eq(result, 0);

    result = scannable_fingerprint_deserialize(&bob_deserialized,
            axolotl_buffer_data(buffer),
            axolotl_buffer_len(buffer),
            global_context);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(scannable_fingerprint_compare(alice_scannable, bob_deserialized), 1);

    /* Cleanup */
    AXOLOTL_UNREF(alice_identity_key);
    AXOLOTL_UNREF(bob_identity_key);
    AXOLOTL_UNREF(alice_scannable);
    AXOLOTL_UNREF(bob_scannable);
    AXOLOTL_UNREF(bob_deserialized);
    axolotl_buffer_free(buffer);
}
END_TEST

START_TEST(test_expected_fingerprints)
{
    int result = 0;
    ec_public_key *alice_identity_key = 0;
    ec_public_key *bob_identity_key = 0;
    fingerprint_generator *generator = 0;
    fingerprint *alice_fingerprint = 0;

    uint8_t alicePublic[] = {
            0x05, 0xBB, 0x9D, 0xAD, 0xC3, 0xF2, 0x91,
            0x72, 0x6F, 0x91, 0xB7, 0x64, 0xA0, 0x2D,
            0x9A, 0x2C, 0x3A, 0x3C, 0xD0, 0xE1, 0x3D,
            0x6A, 0x52, 0x70, 0x88, 0x9A, 0x65, 0xE7,
            0x17, 0xF5, 0xDB, 0xE5, 0x17};

    uint8_t bobPublic[] = {
            0x05, 0x20, 0x83, 0x88, 0xDC, 0xF7, 0x23,
            0x68, 0xAA, 0xF7, 0x87, 0xC3, 0xF5, 0xD0,
            0x08, 0xAF, 0x3D, 0xFC, 0xB0, 0x20, 0xC3,
            0xF6, 0x81, 0xC2, 0x84, 0x51, 0x1C, 0x23,
            0xB8, 0x16, 0x71, 0x50, 0x05};

    const char *expectedDisplayText =
            "280453495159653131690525187060866674650885177562699606988867";

    uint8_t expectedScannableBytes[] = {
            0x08, 0x00, 0x12, 0x31, 0x0A, 0x21, 0x05, 0xBB, 0x9D, 0xAD, 0xC3,
            0xF2, 0x91, 0x72, 0x6F, 0x91, 0xB7, 0x64, 0xA0, 0x2D, 0x9A, 0x2C,
            0x3A, 0x3C, 0xD0, 0xE1, 0x3D, 0x6A, 0x52, 0x70, 0x88, 0x9A, 0x65,
            0xE7, 0x17, 0xF5, 0xDB, 0xE5, 0x17, 0x12, 0x0C, 0x2B, 0x31, 0x34,
            0x31, 0x35, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x1A, 0x31,
            0x0A, 0x21, 0x05, 0x20, 0x83, 0x88, 0xDC, 0xF7, 0x23, 0x68, 0xAA,
            0xF7, 0x87, 0xC3, 0xF5, 0xD0, 0x08, 0xAF, 0x3D, 0xFC, 0xB0, 0x20,
            0xC3, 0xF6, 0x81, 0xC2, 0x84, 0x51, 0x1C, 0x23, 0xB8, 0x16, 0x71,
            0x50, 0x05, 0x12, 0x0C, 0x2B, 0x31, 0x34, 0x31, 0x35, 0x33, 0x33,
            0x33, 0x33, 0x33, 0x33, 0x33
    };

    result = curve_decode_point(&alice_identity_key, alicePublic, sizeof(alicePublic), global_context);
    ck_assert_int_eq(result, 0);

    result = curve_decode_point(&bob_identity_key, bobPublic, sizeof(bobPublic), global_context);
    ck_assert_int_eq(result, 0);

    result = fingerprint_generator_create(&generator, 1024, global_context);
    ck_assert_int_eq(result, 0);

    result = fingerprint_generator_create_for(generator,
            "+14152222222", alice_identity_key,
            "+14153333333", bob_identity_key,
            &alice_fingerprint);
    ck_assert_int_eq(result, 0);

    displayable_fingerprint *alice_displayable = fingerprint_get_displayable(alice_fingerprint);

    ck_assert_str_eq(
            displayable_fingerprint_text(alice_displayable),
            expectedDisplayText);

    scannable_fingerprint *alice_scannable = fingerprint_get_scannable(alice_fingerprint);

    axolotl_buffer *buffer = 0;
    scannable_fingerprint_serialize(&buffer, alice_scannable);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(axolotl_buffer_len(buffer), sizeof(expectedScannableBytes));
    ck_assert_int_eq(memcmp(axolotl_buffer_data(buffer), expectedScannableBytes, sizeof(expectedScannableBytes)), 0);

    /* Cleanup */
    axolotl_buffer_free(buffer);
    fingerprint_generator_free(generator);
    AXOLOTL_UNREF(alice_identity_key);
    AXOLOTL_UNREF(bob_identity_key);
    AXOLOTL_UNREF(alice_fingerprint);
}
END_TEST

START_TEST(test_matching_fingerprints)
{
    int result = 0;
    ec_public_key *alice_identity_key = create_test_ec_public_key(global_context);
    ec_public_key *bob_identity_key = create_test_ec_public_key(global_context);
    fingerprint_generator *generator = 0;
    fingerprint *alice_fingerprint = 0;
    fingerprint *bob_fingerprint = 0;

    result = fingerprint_generator_create(&generator, 1024, global_context);
    ck_assert_int_eq(result, 0);

    result = fingerprint_generator_create_for(generator,
            "+14152222222", alice_identity_key,
            "+14153333333", bob_identity_key,
            &alice_fingerprint);
    ck_assert_int_eq(result, 0);

    result = fingerprint_generator_create_for(generator,
            "+14153333333", bob_identity_key,
            "+14152222222", alice_identity_key,
            &bob_fingerprint);
    ck_assert_int_eq(result, 0);

    displayable_fingerprint *alice_displayable = fingerprint_get_displayable(alice_fingerprint);
    displayable_fingerprint *bob_displayable = fingerprint_get_displayable(bob_fingerprint);

    ck_assert_str_eq(
            displayable_fingerprint_text(alice_displayable),
            displayable_fingerprint_text(bob_displayable));

    scannable_fingerprint *alice_scannable = fingerprint_get_scannable(alice_fingerprint);
    scannable_fingerprint *bob_scannable = fingerprint_get_scannable(bob_fingerprint);

    ck_assert_int_eq(scannable_fingerprint_compare(alice_scannable, bob_scannable), 1);
    ck_assert_int_eq(scannable_fingerprint_compare(bob_scannable, alice_scannable), 1);

    ck_assert_int_eq(strlen(displayable_fingerprint_text(alice_displayable)), 60);

    /* Cleanup */
    fingerprint_generator_free(generator);
    AXOLOTL_UNREF(alice_identity_key);
    AXOLOTL_UNREF(bob_identity_key);
    AXOLOTL_UNREF(alice_fingerprint);
    AXOLOTL_UNREF(bob_fingerprint);
}
END_TEST

START_TEST(test_mismatching_fingerprints)
{
    int result = 0;
    ec_public_key *alice_identity_key = create_test_ec_public_key(global_context);
    ec_public_key *bob_identity_key = create_test_ec_public_key(global_context);
    ec_public_key *mitm_identity_key = create_test_ec_public_key(global_context);
    fingerprint_generator *generator = 0;
    fingerprint *alice_fingerprint = 0;
    fingerprint *bob_fingerprint = 0;

    result = fingerprint_generator_create(&generator, 1024, global_context);
    ck_assert_int_eq(result, 0);

    result = fingerprint_generator_create_for(generator,
            "+14152222222", alice_identity_key,
            "+14153333333", mitm_identity_key,
            &alice_fingerprint);
    ck_assert_int_eq(result, 0);

    result = fingerprint_generator_create_for(generator,
            "+14153333333", bob_identity_key,
            "+14152222222", alice_identity_key,
            &bob_fingerprint);
    ck_assert_int_eq(result, 0);

    displayable_fingerprint *alice_displayable = fingerprint_get_displayable(alice_fingerprint);
    displayable_fingerprint *bob_displayable = fingerprint_get_displayable(bob_fingerprint);

    ck_assert_str_ne(
            displayable_fingerprint_text(alice_displayable),
            displayable_fingerprint_text(bob_displayable));

    scannable_fingerprint *alice_scannable = fingerprint_get_scannable(alice_fingerprint);
    scannable_fingerprint *bob_scannable = fingerprint_get_scannable(bob_fingerprint);

    ck_assert_int_ne(scannable_fingerprint_compare(alice_scannable, bob_scannable), 1);
    ck_assert_int_ne(scannable_fingerprint_compare(bob_scannable, alice_scannable), 1);

    /* Cleanup */
    fingerprint_generator_free(generator);
    AXOLOTL_UNREF(alice_identity_key);
    AXOLOTL_UNREF(bob_identity_key);
    AXOLOTL_UNREF(mitm_identity_key);
    AXOLOTL_UNREF(alice_fingerprint);
    AXOLOTL_UNREF(bob_fingerprint);
}
END_TEST

START_TEST(test_mismatching_identifiers)
{
    int result = 0;
    ec_public_key *alice_identity_key = create_test_ec_public_key(global_context);
    ec_public_key *bob_identity_key = create_test_ec_public_key(global_context);
    fingerprint_generator *generator = 0;
    fingerprint *alice_fingerprint = 0;
    fingerprint *bob_fingerprint = 0;

    result = fingerprint_generator_create(&generator, 1024, global_context);
    ck_assert_int_eq(result, 0);

    result = fingerprint_generator_create_for(generator,
            "+14152222222", alice_identity_key,
            "+1415333333", bob_identity_key,
            &alice_fingerprint);
    ck_assert_int_eq(result, 0);

    result = fingerprint_generator_create_for(generator,
            "+14153333333", bob_identity_key,
            "+14152222222", alice_identity_key,
            &bob_fingerprint);
    ck_assert_int_eq(result, 0);

    displayable_fingerprint *alice_displayable = fingerprint_get_displayable(alice_fingerprint);
    displayable_fingerprint *bob_displayable = fingerprint_get_displayable(bob_fingerprint);

    ck_assert_str_ne(
            displayable_fingerprint_text(alice_displayable),
            displayable_fingerprint_text(bob_displayable));

    scannable_fingerprint *alice_scannable = fingerprint_get_scannable(alice_fingerprint);
    scannable_fingerprint *bob_scannable = fingerprint_get_scannable(bob_fingerprint);

    ck_assert_int_eq(scannable_fingerprint_compare(alice_scannable, bob_scannable), AX_ERR_FP_IDENT_MISMATCH);
    ck_assert_int_eq(scannable_fingerprint_compare(bob_scannable, alice_scannable), AX_ERR_FP_IDENT_MISMATCH);

    /* Cleanup */
    fingerprint_generator_free(generator);
    AXOLOTL_UNREF(alice_identity_key);
    AXOLOTL_UNREF(bob_identity_key);
    AXOLOTL_UNREF(alice_fingerprint);
    AXOLOTL_UNREF(bob_fingerprint);
}
END_TEST

Suite *fingerprint_suite(void)
{
    Suite *suite = suite_create("fingerprint");

    TCase *tcase = tcase_create("case");
    tcase_add_checked_fixture(tcase, test_setup, test_teardown);
    tcase_add_test(tcase, test_scannable_fingerprint_serialize);
    tcase_add_test(tcase, test_expected_fingerprints);
    tcase_add_test(tcase, test_matching_fingerprints);
    tcase_add_test(tcase, test_mismatching_fingerprints);
    tcase_add_test(tcase, test_mismatching_identifiers);
    suite_add_tcase(suite, tcase);

    return suite;
}

int main(void)
{
    int number_failed;
    Suite *suite;
    SRunner *runner;

    suite = fingerprint_suite();
    runner = srunner_create(suite);

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
