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
#include "secureflags.h"
#include "various_consts.h"

/*
 * Return value:
 *    False: Access granted.
 *    True:  Access denied.
 */
bool dropkin_check_filepac(DROPKIN_credx_t *pt, DROPKIN_inode_t *ino, int mask) {
	u32 f_res_type_id, rights;
	int i;
	
	/*
	 * If the target file is a process, check access it.
	 */
	if(ino->is_process) passmls(pt->subject,ino->process,true);
	
	/*
	 * Perform Capability Based Access Control (CBAC or CAPSEC).
	 */
	if(pt->secure_flags&SECF_NO_NEEDCAPS) {
		
		f_res_type_id = cap2rti(ino->res_type_id);
		
		if(f_res_type_id) {
			
			/*
			 * Set rights vector to 0.
			 */
			rights = 0;
			
			/*
			 * Loop thru all Capabilities of the process, and pick that one, with
			 * the RTI of the file.
			 */
			for(i=0;i<MAX_RES_TYPE_CAPS;++i) {
				if( f_res_type_id == cap2rti(pt->res_type_caps[i]) ) {
					rights = cap2rights(pt->res_type_caps[i]);
					break;
				}
			}
			
			/*
			 * Now, lets check all access rights. One by one.
			 */
			if( (mask & MAY_EXEC  ) && !(rights & CAP_EXEC  ) ) return true;
			if( (mask & MAY_READ  ) && !(rights & CAP_READ  ) ) return true;
			if( (mask & MAY_WRITE ) && !(rights & CAP_WRITE ) ) return true;
			if( (mask & MAY_APPEND) && !(rights & (CAP_WRITE|CAP_APPEND)) ) return true;
			if( (mask &xMAY_DELETE) && !(rights & CAP_DELETE) ) return true;
			if( (mask &xMAY_LINK  ) && !(rights & CAP_LINK  ) ) return true;
			if( (mask &xMAY_RENAME) && !(rights & CAP_RENAME) )
				/*
				 * If the Rename-Capability is missing, a combination of CAP_DELETE and CAP_LINK
				 * can be used instead, as rename() can be emulated through link() and unlink() anyways.
				 */
				if(!( (rights & CAP_DELETE) && (rights & CAP_LINK)  )) return true;
			
		} else if(mask&(MAY_WRITE|MAY_APPEND)) return true;
	}
	
	return false;
}

void dropkin_repr_as_file(DROPKIN_credx_t *pt, DROPKIN_inode_t *ino) {
	
	ino->process = pt->subject;
	
	ino->is_process = true;
}
