#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "hash.h"

static TEE_Result sha_arithmetic(uint32_t mode, void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len)
{
	TEE_Result res;
	TEE_OperationHandle op;
	uint32_t keysize = 0;
	
	switch (mode)
	{
		case TEE_ALG_SHA1:
			keysize = 160;
			break;
		case TEE_ALG_SHA224:
			keysize = 224;
			break;
		case TEE_ALG_SHA256:
			keysize = 256;
			break;
		case TEE_ALG_SHA384:
			keysize = 384;
			break;
		case TEE_ALG_SHA512:
			keysize = 512;
			break;
		case TEE_ALG_SM3:
			keysize = 256;
			break;
		default:
			break;
	}

	res = TEE_AllocateOperation(&op, mode, TEE_MODE_DIGEST, 0);
	if (res) {
		EMSG("%s error!!! exit. res=0x%x", __func__, res);
		return res;
	}

	while (inbuf_len > (512/8)) {
		TEE_DigestUpdate(op, inbuf, (512/8));
		inbuf_len -= (512/8);
		inbuf += (512/8);
	}

	*outbuf_len = keysize / 8;
	res = TEE_DigestDoFinal(op, inbuf, inbuf_len, outbuf, outbuf_len);

	TEE_FreeOperation(op);

	return res;

}

#define SHA(name) \
TEE_Result sha##name(void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len) \
{ \
	return sha_arithmetic(TEE_ALG_SHA##name, inbuf, inbuf_len, outbuf, outbuf_len); \
}

SHA(1)
SHA(224)
SHA(256)
SHA(384)
SHA(512)

TEE_Result sm3(void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len)
{
	return sha_arithmetic(TEE_ALG_SM3, inbuf, inbuf_len, outbuf, outbuf_len);
}