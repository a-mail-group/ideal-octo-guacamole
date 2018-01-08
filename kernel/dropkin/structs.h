#pragma once
/*
 *  Copyright (C) 2017-2018 Simon Schmidt
 *
 *	This code is public domain; you can redistribute it and/or modify
 *	it under the terms of the Creative Commons "CC0" license. See LICENSE.CC0
 *	or <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 *	Alternatively, you can use this software under the terms of the
 *	GNU General Public License version 2, as published by the
 *	Free Software Foundation.
 *
**/

#include <linux/types.h>

typedef struct DROPKIN_subject_s {
	/*
	 * Protection Ring (aka security level) for Multi Level Security (MLS).
	 * Bigger number == Lower privilege. (Inspired by ring 0.) 
	 */
	u32 prot_ring;
	/*
	 * Isolation ID.
	 */
	u32 iso_id;
} DROPKIN_subject_t;

typedef u32 DROPKIN_CAP;
#define cap2rti(x) (DROPKIN_CAP)((x)>>8)
#define rti2cap(x) (DROPKIN_CAP)((x)<<8)
#define cap2rights(x) (DROPKIN_CAP)((x)&0xff)
#define rights2cap(x) (DROPKIN_CAP)((x)&0xff)


#define MAX_RES_TYPE_CAPS 28 /* 32-4 = 28 */

typedef struct DROPKIN_credx_s {
	u32 pledge;
	DROPKIN_subject_t subject;
	u32 secure_flags;
	/*
	 * Resource-Type-Capabilities.
	 *
	 * This is needed to implement Capability Based Access Control.
	 */
	DROPKIN_CAP res_type_caps[MAX_RES_TYPE_CAPS];
} DROPKIN_credx_t;

typedef struct DROPKIN_sysv_s {
	DROPKIN_subject_t subject;
	bool associated;
} DROPKIN_sysv_t;

typedef struct DROPKIN_inode_s {
	/*
	 * This field is used, if the inode represents a Process.
	 */
	DROPKIN_subject_t process;
	
	/*
	 * Resource-Type-Id
	 *
	 * If this one is set to ZERO (default), The file does not have an Type-Id.
	 *
	 * This value is encoded as a DROPKIN_CAP. It must be set with rti2cap( type-num ) .
	 *
	 * The rights vector, cap2rights( res_type_id ) will be ignored, and should be ZERO.
	 */
	DROPKIN_CAP res_type_id;
	/*
	 * Locks for Files and Directories (not in terms of synchronization).
	 *
	 * These flags determine, what a (deprivileged) process can do with this file, and what not.
	 */
	u32 lockflags;
	/* Insert new fields here... */
	bool is_process;
} DROPKIN_inode_t;

typedef struct DROPKIN_socket_s {
	DROPKIN_subject_t owner;
	u32 secure_flags;
} DROPKIN_socket_t;

