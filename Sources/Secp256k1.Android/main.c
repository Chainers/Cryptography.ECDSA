#include "main.h"

#include "include/secp256k1.h"
#include "include/secp256k1_recovery.h"
#include "hash.h"
#include "hash_impl.h"

void get_message_hash(const unsigned char *data, const size_t sz, unsigned char *output_ser) {
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	secp256k1_sha256_write(&sha, data, sz);
	secp256k1_sha256_finalize(&sha, output_ser);
}

int sign_compact(const secp256k1_context* ctx, const unsigned char *msg32, const unsigned char *seckey, unsigned char *output64, int *recid) {
	secp256k1_ecdsa_recoverable_signature sig;
	char loop = -1;
	int index = 0;
	int rec = 0;
	unsigned char extra[32] = { 0x00 };
	do
	{
		loop = loop + 1;
		extra[index] = loop;
		if (extra[index] == 0xff)
			index = index + 1;
		
		rec = secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg32, seckey, NULL, extra);
		
	} while (!rec && !is_canonical(&sig));

	secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output64, recid, &sig);
	return loop;
}

int is_canonical(const unsigned char * sig) {
	return !(sig[0] & 0x80)
		&& !(sig[0] == 0 && !(sig[1] & 0x80))
		&& !(sig[32] & 0x80)
		&& !(sig[32] == 0 && !(sig[33] & 0x80));
}