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
#include <linux/fs.h>
#include "filepac.h"
#include "mls.h"
#include "macros.h"

/*
 * Return value:
 *    False: Access granted.
 *    True:  Access denied.
 */
bool dropkin_check_filepac(DROPKIN_credx_t *pt, DROPKIN_inode_t *object, int mask) {
	
	// TODO: The policy is idiotic right now, refine it.
	passmlsf(pt->subject,object,bcast(mask&MAY_WRITE),bcast(mask&(MAY_READ|MAY_EXEC)),true);
	
	return false;
}


void dropkin_repr_as_file(DROPKIN_credx_t *pt, DROPKIN_inode_t *ins){
	ins->general_pr = ins->read_pr = ins->write_pr = pt->subject.prot_ring;
	ins->iso_id = pt->subject.iso_id;
}
