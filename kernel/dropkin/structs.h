#pragma once
/*
 *  Copyright (C) 2017 Simon Schmidt
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

typedef struct DROPKIN_credx_s {
	u32 pledge;
	DROPKIN_subject_t subject;
} DROPKIN_credx_t;

typedef struct DROPKIN_sysv_s {
	DROPKIN_subject_t subject;
	bool associated;
} DROPKIN_sysv_t;

typedef struct DROPKIN_inode_s {
	/*
	 * Protection rings.
	 */
	u32 general_pr;
	u32 read_pr;
	u32 write_pr;
	/*
	 * Isolation ID.
	 */
	u32 iso_id;
} DROPKIN_inode_t;

