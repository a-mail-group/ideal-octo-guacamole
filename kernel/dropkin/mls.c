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
#include "mls.h"

int dropkin_check_mls(DROPKIN_subject_t *subject,DROPKIN_subject_t *object){
	/*
	 * Check, if we are violating the Multi-Level security constraints.
	 * Bigger number == Lower privilege. (Inspired by ring 0.)
	 */
	if( (subject->prot_ring) > (object->prot_ring) ) return -1;
	
	/*
	 * Check, if we are violating the Isolation constraints.
	 */
	if( ((subject->iso_id) != 0u) && (subject->iso_id) != (object->iso_id) ) return -1;
	
	return 0;
}

// XXX: Considered Legacy.
bool dropkin_check_mlsf(DROPKIN_subject_t *subject, DROPKIN_inode_t *object, bool read,bool write) {
	/*
	 * Check, if we are violating the Multi-Level security constraints.
	 * Bigger number == Lower privilege. (Inspired by ring 0.)
	 */
	
	/* Check the read security level. */
	if( read && (subject->prot_ring) > (object->mls.read_pr) ) return true;
	
	/* Check the write security level. */
	if( write && (subject->prot_ring) > (object->mls.write_pr) ) return true;
	
	
	return false;
}

