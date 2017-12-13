#pragma once
/*
 * File <=> Process Access Control.
 *
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
#include "structs.h"

#define xMAY_DELETE 0x00010000
#define xMAY_RENAME 0x00020000
#define xMAY_LINK   0x00040000

/*
 * Return value:
 *    False: Access granted.
 *    True:  Access denied.
 */
bool dropkin_check_filepac(DROPKIN_credx_t *pt, DROPKIN_inode_t *object, int mask);

#define passfilepac(credx,ino,mask,x) if(dropkin_check_filepac((DROPKIN_credx_t *)(credx),ino,mask)) return x

/*
 * Represent a process (pt) as file (object) in procfs.
 */
void dropkin_repr_as_file(DROPKIN_credx_t *pt, DROPKIN_inode_t *object);

