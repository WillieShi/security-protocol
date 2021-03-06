#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "minunit.h"
#include <strong-arm/strong-arm.h>

int tests_run = 0;

char *test_finite_field (void);
char *test_ecdsa (void);
char *test_ripemd160 (void);
char *test_sha256 (void);
char *test_base58 (void);
char *test_random (void);
char *test_hmac (void);
char *test_pbkdf2 (void);
char *test_drbg (void);
char *test_aes (void);
char *test_keychain (void);
char *test_threefish (void);


static char *all_tests ()
{
	char *msg;


	if ((msg = test_finite_field ())) return msg;
	if ((msg = test_ecdsa ())) return msg;
	if ((msg = test_keychain ())) return msg;
	if ((msg = test_ripemd160 ())) return msg;
	if ((msg = test_sha256 ())) return msg;
	if ((msg = test_base58 ())) return msg;
	if ((msg = test_random ())) return msg;
	if ((msg = test_hmac ())) return msg;
	if ((msg = test_pbkdf2())) return msg;
	if ((msg = test_drbg ())) return msg;
	if ((msg = test_aes ())) return msg;
	if ((msg = test_threefish ())) return msg;
	
	return 0;
}


int main (void)
{
	strongarm_init ();
	
	char *result = all_tests ();
	
	if (result != 0)
		printf ("%s\n", result);
	else
		printf ("ALL TESTS PASSED\n");
	printf ("Tests run: %d\n", tests_run);
	
	return result != 0;
}
