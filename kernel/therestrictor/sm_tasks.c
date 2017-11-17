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

/* for malloc() */
#include <linux/slab.h>

#include <linux/sched.h>
#include <linux/cred.h>
#include "entry_points.h"
#include "structs.h"
#include "prctl_numbers.h"
#include "macros.h"
#include "pledge.h"

int therest_cred_alloc_blank(struct cred *cred, gfp_t gfp) {
	THEREST_credx_t *t;
	t = kzalloc(sizeof(THEREST_credx_t),gfp);
	if(!t)return -ENOMEM;
	cred->security = t;
	return 0;
}
void therest_cred_free (struct cred *cred){
	THEREST_credx_t *t;
	t = cred->security;
	if(t)kfree(t);
}


// THEREST_credx_t
int therest_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	THEREST_credx_t *t;
	u32 pledge;
	if(!(current->cred->security)) return -ENOSYS;
	
	t = current->cred->security;
	
	pledge = (u32)arg2;
	
	switch(option){
		caseof(PRX_TR_PLEDGE    , t->pledge |= ~pledge );
		caseof(PRX_TR_PLEDGE_NOT, t->pledge |=  pledge );
		caseof(PRX_TR_ABORT     , return E_ABORT       );
	}
	return -ENOSYS;
}

