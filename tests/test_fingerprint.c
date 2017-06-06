#include <check.h>

#include "../src/signal_protocol.h"
#include "curve.h"
#include "fingerprint.h"
#include "test_common.h"

signal_context *global_context;

void test_setup()
{
    int result;
    result = signal_context_create(&global_context, 0);
    ck_assert_int_eq(result, 0);
    signal_context_set_log_function(global_context, test_log);
    setup_test_crypto_provider(global_context);
}

void test_teardown()
{
    signal_context_destroy(global_context);
}

START_TEST(test_scannable_fingerprint_serialize)
{
    int result = 0;
    ec_public_key *alice_identity_key = create_test_ec_public_key(global_context);
    ec_public_key *bob_identity_key = create_test_ec_public_key(global_context);
    signal_buffer *alice_identity_buffer = 0;
    signal_buffer *bob_identity_buffer = 0;
    scannable_fingerprint *alice_scannable = 0;
    scannable_fingerprint *bob_scannable = 0;
    signal_buffer *buffer = 0;
    scannable_fingerprint *bob_deserialized = 0;

    result = ec_public_key_serialize(&alice_identity_buffer, alice_identity_key);
    ck_assert_int_eq(result, 0);

    result = ec_public_key_serialize(&bob_identity_buffer, bob_identity_key);
    ck_assert_int_eq(result, 0);

    result = scannable_fingerprint_create(&alice_scannable, 1,
            "+14152222222", alice_identity_buffer,
            "+14153333333", bob_identity_buffer);
    ck_assert_int_eq(result, 0);

    result = scannable_fingerprint_create(&bob_scannable, 1,
            "+14153333333", bob_identity_buffer,
            "+14152222222", alice_identity_buffer);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(scannable_fingerprint_compare(alice_scannable, bob_scannable), 1);

    result = scannable_fingerprint_serialize(&buffer, bob_scannable);
    ck_assert_int_eq(result, 0);

    result = scannable_fingerprint_deserialize(&bob_deserialized,
            signal_buffer_data(buffer),
            signal_buffer_len(buffer),
            global_context);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(scannable_fingerprint_compare(alice_scannable, bob_deserialized), 1);

    /* Cleanup */
    SIGNAL_UNREF(alice_identity_key);
    SIGNAL_UNREF(bob_identity_key);
    SIGNAL_UNREF(alice_scannable);
    SIGNAL_UNREF(bob_scannable);
    SIGNAL_UNREF(bob_deserialized);
    signal_buffer_free(alice_identity_buffer);
    signal_buffer_free(bob_identity_buffer);
    signal_buffer_free(buffer);
}
END_TEST

START_TEST(test_vectors)
{
    int result = 0;
    ec_public_key *alice_identity_key = 0;
    ec_public_key *bob_identity_key = 0;
    fingerprint_generator *generator = 0;
    fingerprint *alice_fingerprint = 0;
    fingerprint *bob_fingerprint = 0;
    signal_buffer *alice_buffer = 0;
    signal_buffer *bob_buffer = 0;

    uint8_t aliceIdentity[] = {
            0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4,
            0x0d, 0x27, 0xb8, 0xd4, 0x9c, 0xa7, 0xc0, 0x9e,
            0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6,
            0xfc, 0xca, 0x5c, 0xe1, 0x3c, 0x70, 0x64, 0xd8,
            0x68};

    uint8_t bobIdentity[] = {
            0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9,
            0xba, 0x1c, 0xf2, 0xde, 0x97, 0x8d, 0x4d, 0x5d,
            0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81, 0x44,
            0x02, 0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90,
            0x7b};

    const char *displayableFingerprint =
            "300354477692869396892869876765458257569162576843440918079131";

    uint8_t aliceScannableFingerprint[] = {
            0x08, 0x00, 0x12, 0x31, 0x0a, 0x21, 0x05, 0x06,
            0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d, 0x27,
            0xb8, 0xd4, 0x9c, 0xa7, 0xc0, 0x9e, 0x92, 0x39,
            0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6, 0xfc, 0xca,
            0x5c, 0xe1, 0x3c, 0x70, 0x64, 0xd8, 0x68, 0x12,
            0x0c, 0x2b, 0x31, 0x34, 0x31, 0x35, 0x32, 0x32,
            0x32, 0x32, 0x32, 0x32, 0x32, 0x1a, 0x31, 0x0a,
            0x21, 0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe,
            0xd9, 0xba, 0x1c, 0xf2, 0xde, 0x97, 0x8d, 0x4d,
            0x5d, 0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81,
            0x44, 0x02, 0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda,
            0x90, 0x7b, 0x12, 0x0c, 0x2b, 0x31, 0x34, 0x31,
            0x35, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};

    uint8_t bobScannableFingerprint[] = {
            0x08, 0x00, 0x12, 0x31, 0x0a, 0x21, 0x05, 0xf7,
            0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba, 0x1c,
            0xf2, 0xde, 0x97, 0x8d, 0x4d, 0x5d, 0xa2, 0x8d,
            0xc3, 0x40, 0x46, 0xae, 0x81, 0x44, 0x02, 0xb5,
            0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90, 0x7b, 0x12,
            0x0c, 0x2b, 0x31, 0x34, 0x31, 0x35, 0x33, 0x33,
            0x33, 0x33, 0x33, 0x33, 0x33, 0x1a, 0x31, 0x0a,
            0x21, 0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02,
            0xb4, 0x0d, 0x27, 0xb8, 0xd4, 0x9c, 0xa7, 0xc0,
            0x9e, 0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25,
            0xd6, 0xfc, 0xca, 0x5c, 0xe1, 0x3c, 0x70, 0x64,
            0xd8, 0x68, 0x12, 0x0c, 0x2b, 0x31, 0x34, 0x31,
            0x35, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32};

    result = curve_decode_point(&alice_identity_key, aliceIdentity, sizeof(aliceIdentity), global_context);
    ck_assert_int_eq(result, 0);

    result = curve_decode_point(&bob_identity_key, bobIdentity, sizeof(bobIdentity), global_context);
    ck_assert_int_eq(result, 0);

    result = fingerprint_generator_create(&generator, 5200, global_context);
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
    ck_assert_str_eq(
            displayable_fingerprint_text(alice_displayable),
            displayableFingerprint);

    displayable_fingerprint *bob_displayable = fingerprint_get_displayable(bob_fingerprint);
    ck_assert_str_eq(
            displayable_fingerprint_text(bob_displayable),
            displayableFingerprint);

    scannable_fingerprint *alice_scannable = fingerprint_get_scannable(alice_fingerprint);
    scannable_fingerprint_serialize(&alice_buffer, alice_scannable);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(signal_buffer_len(alice_buffer), sizeof(aliceScannableFingerprint));
    ck_assert_int_eq(memcmp(signal_buffer_data(alice_buffer), aliceScannableFingerprint, sizeof(aliceScannableFingerprint)), 0);

    scannable_fingerprint *bob_scannable = fingerprint_get_scannable(bob_fingerprint);
    scannable_fingerprint_serialize(&bob_buffer, bob_scannable);
    ck_assert_int_eq(result, 0);

    ck_assert_int_eq(signal_buffer_len(bob_buffer), sizeof(bobScannableFingerprint));
    ck_assert_int_eq(memcmp(signal_buffer_data(bob_buffer), bobScannableFingerprint, sizeof(bobScannableFingerprint)), 0);

    /* Cleanup */
    signal_buffer_free(alice_buffer);
    signal_buffer_free(bob_buffer);
    fingerprint_generator_free(generator);
    SIGNAL_UNREF(alice_identity_key);
    SIGNAL_UNREF(bob_identity_key);
    SIGNAL_UNREF(alice_fingerprint);
    SIGNAL_UNREF(bob_fingerprint);
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
    SIGNAL_UNREF(alice_identity_key);
    SIGNAL_UNREF(bob_identity_key);
    SIGNAL_UNREF(alice_fingerprint);
    SIGNAL_UNREF(bob_fingerprint);
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
    SIGNAL_UNREF(alice_identity_key);
    SIGNAL_UNREF(bob_identity_key);
    SIGNAL_UNREF(mitm_identity_key);
    SIGNAL_UNREF(alice_fingerprint);
    SIGNAL_UNREF(bob_fingerprint);
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

    ck_assert_int_eq(scannable_fingerprint_compare(alice_scannable, bob_scannable), SG_ERR_FP_IDENT_MISMATCH);
    ck_assert_int_eq(scannable_fingerprint_compare(bob_scannable, alice_scannable), SG_ERR_FP_IDENT_MISMATCH);

    /* Cleanup */
    fingerprint_generator_free(generator);
    SIGNAL_UNREF(alice_identity_key);
    SIGNAL_UNREF(bob_identity_key);
    SIGNAL_UNREF(alice_fingerprint);
    SIGNAL_UNREF(bob_fingerprint);
}
END_TEST

Suite *fingerprint_suite(void)
{
    Suite *suite = suite_create("fingerprint");

    TCase *tcase = tcase_create("case");
    tcase_add_checked_fixture(tcase, test_setup, test_teardown);
    tcase_add_test(tcase, test_scannable_fingerprint_serialize);
    tcase_add_test(tcase, test_vectors);
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
