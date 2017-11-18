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
//#include "secureflags.h"

/*
 * Return value:
 *    False: Access granted.
 *    True:  Access denied.
 */
bool dropkin_check_filepac(DROPKIN_credx_t *pt, DROPKIN_inode_t *ino, int mask) {
	/*
	 * If the target file is a process, check access it.
	 */
	if(ino->is_process) passmls(pt->subject,ino->process,true);
	
	
	/*
	 * Check the write security level.
	 */
	if( (mask&MAY_WRITE) && (pt->subject.prot_ring) > (ino->mls.write_pr) ) return true;
	
	/*
	 * Check the read security level, if this one was offered.
	 */
	if(ino->is_mls_read && (mask&(MAY_READ|MAY_EXEC))
		&& (pt->subject.prot_ring) > (ino->mls.read_pr) ) return true;
	
	return false;
}

void dropkin_repr_as_file(DROPKIN_credx_t *pt, DROPKIN_inode_t *ino) {
	
	ino->process = pt->subject;
	
	ino->is_process = true;
}
