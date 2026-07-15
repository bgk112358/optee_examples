/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Access control module.
 * Validates that a requested operation is allowed on a given key
 * based on its permission bitmask.
 */

#include <inttypes.h>

#include <tee_internal_api.h>

#include "tbox_keystore_ta.h"

/*
 * Check permission for an operation.
 * Returns TEE_SUCCESS if allowed, TEE_ERROR_ACCESS_DENIED otherwise.
 */
TEE_Result acl_check(uint32_t permissions, uint32_t required_perm)
{
	if ((permissions & required_perm) != required_perm) {
		EMSG("Permission denied: need 0x%x, have 0x%x",
		     (unsigned int)required_perm,
		     (unsigned int)permissions);
		return TEE_ERROR_ACCESS_DENIED;
	}
	return TEE_SUCCESS;
}
