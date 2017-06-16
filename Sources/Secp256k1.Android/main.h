# ifdef __cplusplus
extern "C" {
# endif

#include "include/secp256k1_recovery.h"
#include "secp256k1.h"

void get_message_hash(const unsigned char *data, const size_t sz, unsigned char *output_ser);
int sign_compact(const secp256k1_context* ctx, const unsigned char *msg32, const unsigned char *seckey, unsigned char *output64, int *recid);
int is_canonical(const unsigned char * sig);

# ifdef __cplusplus
}
# endif
