#include "include/secp256k1.h"
#include "include/secp256k1_recovery.h"
#include "hash.h"
#include "hash_impl.h"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Secp256k1
{
	/// <summary>Encapsulates secp256k1 signature related operations</summary>
	public ref class Signatures
	{
		static Signatures()
		{
			Context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
		}
		static String ^PrivateKeyLengthError = "Private key must be 32 bytes long.";
		static String ^CompactSignatureLengthError = "Compact signatures must be 64 bytes long.";
		static String ^MessageLengthError = "Message must be 32 bytes long (SHA-256 it!)";
		static secp256k1_context *Context;

		static array<Byte> ^SerializePublicKey(const secp256k1_pubkey *publicKey, bool compressed)
		{
			array<Byte> ^pubkey = gcnew array<Byte>(compressed ? 33 : 65);
			size_t pubkeylen = pubkey->Length;
			{
				pin_ptr<Byte> pubkeybytes = &pubkey[0];
				if (!secp256k1_ec_pubkey_serialize(Context, pubkeybytes, &pubkeylen, publicKey, compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))
					return nullptr;
			}
			if (pubkeylen == pubkey->Length)
				return pubkey;
			array<Byte> ^smallkey = gcnew array<Byte>(pubkeylen);
			array<Byte>::Copy(pubkey, 0, smallkey, 0, pubkeylen);
			return smallkey;
		}
		static array<Byte> ^SerializeSignature(const secp256k1_ecdsa_signature *signature)
		{
			array<Byte> ^sigbytes = gcnew array<Byte>(70);
			size_t sigptrlen = sigbytes->Length;
			{
				pin_ptr<Byte> sigptr = &sigbytes[0];
				if (!secp256k1_ecdsa_signature_serialize_der(Context, sigptr, &sigptrlen, signature))
					if (sigptrlen > (size_t)sigbytes->Length)
					{
						sigbytes = gcnew array<Byte>(sigptrlen);
						sigptr = &sigbytes[0];
						if (!secp256k1_ecdsa_signature_serialize_der(Context, sigptr, &sigptrlen, signature))
							return nullptr;
					}
					else
						return nullptr;
			}
			if (sigptrlen == sigbytes->Length)
				return sigbytes;
			array<Byte> ^smallsignature = gcnew array<Byte>(sigptrlen);
			array<Byte>::Copy(sigbytes, 0, smallsignature, 0, sigptrlen);
			return smallsignature;
		}

	public:
		/// <summary>Verifies that a signature is valid.</summary>
		/// <param name="message">The message to verify.  This data is not hashed.  For use with bitcoins, you probably want to double-SHA256 hash this before calling this method.</param>
		/// <param name="signature">The signature to test for validity. This must not be a compact key (Use RecoverKeyFromCompact instead).</param>
		/// <param name="publicKey">The public key used to create the signature.</param>
		/// <param name="normalizeSignatureOnFailure">If the signature appears invalid, normalize it to lower-S form and try again before declaring it invalid.</param>
		static bool Verify(array<Byte> ^message, array<Byte> ^signature, array<Byte> ^publicKey, bool normalizeSignatureOnFailure)
		{
			if (message == nullptr || signature == nullptr || publicKey == nullptr)
				throw gcnew ArgumentNullException();
			if (message->Length != 32)
				throw gcnew ArgumentOutOfRangeException(MessageLengthError);

			secp256k1_ecdsa_signature sig;
			secp256k1_pubkey key;

			{
				pin_ptr<Byte> keyptr = &publicKey[0];
				if (!secp256k1_ec_pubkey_parse(Context, &key, keyptr, publicKey->Length))
					return false;
			}
			{
				pin_ptr<Byte> signatureptr = &signature[0];
				if (!secp256k1_ecdsa_signature_parse_der(Context, &sig, signatureptr, signature->Length))
					return false;
			}

			pin_ptr<Byte> messageptr = &message[0];
			if (!secp256k1_ecdsa_verify(Context, &sig, messageptr, &key))
			{
				if (!normalizeSignatureOnFailure)
					return false;
				secp256k1_ecdsa_signature normalized;
				if (!secp256k1_ecdsa_signature_normalize(Context, &normalized, &sig))
					return false;
				if (!secp256k1_ecdsa_verify(Context, &normalized, messageptr, &key))
					return false;
			}
			return true;
		}
		/// <summary>Signs a message and returns the signature.  Returns null on failure.</summary>
		/// <param name="message">The message to sign.  This data is not hashed.  For use with bitcoins, you probably want to double-SHA256 hash this before calling this method.</param>
		/// <param name="privateKey">The private key to use to sign the message.</param>
		static array<Byte> ^Sign(array<Byte> ^message, array<Byte> ^privateKey)
		{
			if (message == nullptr || privateKey == nullptr)
				throw gcnew ArgumentNullException();
			if (privateKey->Length != 32)
				throw gcnew ArgumentOutOfRangeException(PrivateKeyLengthError);
			if (message->Length != 32)
				throw gcnew ArgumentOutOfRangeException(MessageLengthError);

			secp256k1_ecdsa_signature sig;
			{
				pin_ptr<Byte> messageptr = &message[0];
				pin_ptr<Byte> keyptr = &privateKey[0];
				if (!secp256k1_ecdsa_sign(Context, &sig, messageptr, keyptr, 0, 0))
					return nullptr;
			}
			return SerializeSignature(&sig);
		}
		/// <summary>Signs a message and returns the signature in compact form.  Returns null on failure.</summary>
		/// <param name="message">The message to sign.  This data is not hashed.  For use with bitcoins, you probably want to double-SHA256 hash this before calling this method.</param>
		/// <param name="privateKey">The private key to use to sign the message.</param>
		/// <param name="recoveryId">This will contain the recovery ID needed to retrieve the key from the compact signature using the RecoverKeyFromCompact method.</param> 
		static array<Byte> ^SignCompact(array<Byte> ^message, array<Byte> ^privateKey, [Out] int %recoveryId)
		{
			if (message == nullptr || privateKey == nullptr)
				throw gcnew ArgumentNullException();
			if (privateKey->Length != 32)
				throw gcnew ArgumentOutOfRangeException(PrivateKeyLengthError);
			if (message->Length != 32)
				throw gcnew ArgumentOutOfRangeException(MessageLengthError);

			recoveryId = 0;

			secp256k1_ecdsa_recoverable_signature sig;
			{
				pin_ptr<Byte> messageptr = &message[0];
				pin_ptr<Byte> keyptr = &privateKey[0];
				if (!secp256k1_ecdsa_sign_recoverable(Context, &sig, messageptr, keyptr, 0, 0))
					return nullptr;
			}
			array<Byte> ^sigbytes = gcnew array<Byte>(64);
			int recid;
			{
				pin_ptr<Byte> sigptr = &sigbytes[0];
				if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(Context, sigptr, &recid, &sig))
					return nullptr;
			}
			recoveryId = recid;
			return sigbytes;
		}
		/// <summary>Recovers a public key from a compact signature.  Success also indicates a valid signature.  Returns null on failure.</summary>
		/// <param name="message">The message that was signed.  This data is not hashed.  For use with bitcoins, you probably want to double-SHA256 hash this before calling this method.</param>
		/// <param name="signature">The signature provided that will also be tested for validity.  A return value other than null indicates this signature is valid.</param>
		/// <param name="recoveryId">The recovery ID provided during a call to the SignCompact method.</param>
		/// <param name="compressed">True if the public key is to be compressed.</param>
		static array<Byte> ^RecoverKeyFromCompact(array<Byte> ^message, array<Byte> ^signature, int recoveryId, bool compressed)
		{
			if (message == nullptr || signature == nullptr)
				throw gcnew ArgumentNullException();
			if (signature->Length != 64)
				throw gcnew ArgumentOutOfRangeException(CompactSignatureLengthError);
			if (message->Length != 32)
				throw gcnew ArgumentOutOfRangeException(MessageLengthError);

			secp256k1_ecdsa_recoverable_signature sig;
			{
				pin_ptr<Byte> sigptr = &signature[0];
				if (!secp256k1_ecdsa_recoverable_signature_parse_compact(Context, &sig, sigptr, recoveryId))
					return nullptr;
			}
			secp256k1_pubkey key;
			{
				pin_ptr<Byte> messageptr = &message[0];
				if (!secp256k1_ecdsa_recover(Context, &key, &sig, messageptr))
					return nullptr;
			}
			return SerializePublicKey(&key, compressed);
		}
		/// <summary>Verifies that a private key is valid.  Returns true if valid.</summary>
		/// <param name="privateKey">A private key to test for validity.</param>
		static bool VerifyPrivateKey(array<Byte> ^privateKey)
		{
			if (privateKey == nullptr || privateKey->Length != 32)
				return false;
			pin_ptr<Byte> keyptr = &privateKey[0];
			return secp256k1_ec_seckey_verify(Context, keyptr) == 1;
		}
		/// <summary>Gets the public key associated with a private key.  Returns null on failure.</summary>
		/// <param name="privateKey">The private key from which to extract the public key.</param>
		/// <param name="compressed">True if the public key is to be compressed.</param>
		static array<Byte> ^GetPublicKey(array<Byte> ^privateKey, bool compressed)
		{
			if (privateKey == nullptr)
				throw gcnew ArgumentNullException();
			if (privateKey->Length != 32)
				throw gcnew ArgumentOutOfRangeException(PrivateKeyLengthError);

			secp256k1_pubkey key;
			{
				pin_ptr<Byte> privkeyptr = &privateKey[0];
				if (!secp256k1_ec_pubkey_create(Context, &key, privkeyptr))
					return nullptr;
			}
			return SerializePublicKey(&key, compressed);
		}
		/// <summary>Converts a signature to lower-S form.  Returns null on failure.  Returns the same signature instance if already normalized.  Cannot be a compact signature.</summary>
		/// <param name="signature">The signature to normalize.</param>
		/// <param name="bool">If true, returns the same signature instance. If false, returns the new normalized signature.</param>
		static array<Byte> ^NormalizeSignature(array<Byte> ^signature, [Out] bool %wasAlreadyNormalized)
		{
			if (signature == nullptr)
				throw gcnew ArgumentNullException();

			wasAlreadyNormalized = false;

			secp256k1_ecdsa_signature sig;
			{
				pin_ptr<Byte> signatureptr = &signature[0];
				if (!secp256k1_ecdsa_signature_parse_der(Context, &sig, signatureptr, signature->Length))
					return nullptr;
			}
			secp256k1_ecdsa_signature normalized;
			wasAlreadyNormalized = !secp256k1_ecdsa_signature_normalize(Context, &normalized, &sig);
			if (wasAlreadyNormalized)
				return signature;
			return SerializeSignature(&normalized);
		}
		/// <summary>Use sha256 to get hash from message</summary>
		/// <param name="message">message</param>
		/// <param name="hashcount">For use with bitcoins, you probably want to double-SHA256 hash => hashcount=2</param>
		static array<Byte> ^GetMessageHash(array<Byte> ^message)
		{
			if (message == nullptr)
				throw gcnew ArgumentNullException();

			secp256k1_sha256_t sha;
			array<Byte> ^output_ser = gcnew array<Byte>(32);
			//unsigned char output_ser[32];
			pin_ptr<Byte> data = &message[0];
			pin_ptr<Byte> dataout = &output_ser[0];

			secp256k1_sha256_initialize(&sha);
			secp256k1_sha256_write(&sha, data, message->Length);
			secp256k1_sha256_finalize(&sha, dataout);
			return output_ser;
		}
	};
};