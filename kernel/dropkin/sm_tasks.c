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
#include <linux/mman.h>
#include "entry_points.h"
#include "structs.h"
#include "prctl_numbers.h"
#include "macros.h"
#include "pledge.h"
#include "mls.h"
#include "secureflags.h"

int dropkin_cred_alloc_blank(struct cred *cred, gfp_t gfp) {
	DROPKIN_credx_t *t;
	t = kzalloc(sizeof(DROPKIN_credx_t),gfp);
	if(!t)return -ENOMEM;
	cred->security = t;
	return 0;
}
int dropkin_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp) {
	DROPKIN_credx_t *t;
	DROPKIN_credx_t *ot;
	t = kzalloc(sizeof(DROPKIN_credx_t),gfp);
	if(!t)return -ENOMEM;
	new->security = t;
	
	/* Old process didn't have a CredX? Quit! */
	passnocred(old,0);
	
	/* Copy the CredX. */
	ot = old->security;
	*t=*ot;
	return 0;
}

void dropkin_cred_free (struct cred *cred) {
	DROPKIN_credx_t *t;
	t = cred->security;
	if(t)kfree(t);
}

int dropkin_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid){
	DROPKIN_credx_t *t;
	DROPKIN_credx_t *ot;         
	passnocred(current->cred, 0);
	
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	
	passnocred(p->cred, 0);
	t = current->cred->security;
	ot = p->cred->security;
	
	passmls(t->subject,ot->subject, -EACCES);
	
	return 0;
}
int  dropkin_task_getsid(struct task_struct *p){
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	return 0;
}
int  dropkin_task_setnice(struct task_struct *p, int nice){
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	return 0;
}
int  dropkin_task_setioprio(struct task_struct *p, int ioprio){
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	return 0;
}
int  dropkin_task_getioprio(struct task_struct *p){
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	return 0;
}

int  dropkin_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot) {
	passnocred(current->cred, 0);
	passpledge(PLEDGE_STDIO, E_ABORT);
	if(reqprot&PROT_EXEC) passpledge(PLEDGE_PROT_EXEC, E_ABORT);
	return 0;
}
int  dropkin_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags) {
	passnocred(current->cred, 0);
	passpledge(PLEDGE_STDIO, E_ABORT);
	if(reqprot&PROT_EXEC) passpledge(PLEDGE_PROT_EXEC, E_ABORT);
	return 0;
}

int  dropkin_bprm_check_security(struct linux_binprm *bprm) {
	passnocred(current->cred, 0);
	passpledge(PLEDGE_EXEC, E_ABORT);
	return 0;
}

void dropkin_bprm_committed_creds(struct linux_binprm *bprm) {
	DROPKIN_credx_t *t;
	passnocred(current->cred, );
	t = current->cred->security;
	/*
	 * Clear Pledge!
	 */
	t->pledge = 0;
}

int  dropkin_task_fix_setuid(struct cred *new, const struct cred *old,int flags){
	DROPKIN_credx_t *t;
	DROPKIN_credx_t *ot;
	
	passnocred(new,0);
	passnocred(old,0);
	
	/* Copy! */
	t  = new->security;
	ot = old->security;
	*t=*ot;
	
	if(t->secure_flags&SECF_NO_ROOT) return E_ABORT;
	
	return 0;
}

static int dropkin_find_or_create_cap(DROPKIN_credx_t *pt,u32 rti)
{
	int i;
	for(i=0;i<MAX_RES_TYPE_CAPS;++i){
		if(rti!=cap2rti(pt->res_type_caps[i])) continue; /* Skip entries != rti. */
		return i;
	}
	for(i=0;i<MAX_RES_TYPE_CAPS;++i){
		if( cap2rti(pt->res_type_caps[i]) ) continue; /* Skip entries, that are Non-ZERO. */
		/* Create Capability Entry. */
		pt->res_type_caps[i] = rti2cap(rti);
		return i;
	}
	return -1;
}



int dropkin_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	DROPKIN_credx_t *t;
	u32 pcarg, perms;
	int i;
	//if(!(current->cred->security)) pr_info("DAMN! - no Object!");
	passnocred(current->cred, -ENOSYS);
	//if(!(current->cred->security)) return -ENOSYS;
	
	t = current->cred->security;
	
	pcarg = (u32)arg2;
	perms = (u32)arg3;
	
	switch(option){
		caseof(PRX_TR_PLEDGE     , t->pledge |= ~pcarg );
		caseof(PRX_TR_PLEDGE_NOT , t->pledge |=  pcarg );
		caseof(PRX_TR_ABORT      , return E_ABORT       );
		caseof(PRX_TR_MLS_RING   ,
			if(t->subject.prot_ring>pcarg) return -EACCES;
			t->subject.prot_ring=pcarg );
		caseof(PRX_TR_ISO_ID     ,
			if(t->subject.iso_id) return -EACCES;
			t->subject.iso_id=pcarg );
		caseof(PRX_TR_SET_SECFLAG, t->secure_flags |= pcarg );
		case   PRX_TR_SET_CAP:
			if(t->secure_flags&&SECF_NO_NEEDCAPS) return -EACCES;
			i = dropkin_find_or_create_cap(t,pcarg);
			if(i<0) return -ENOMEM; /* No more space. */
			t->res_type_caps[i] |= rights2cap(perms);
		break;
	}
	return -ENOSYS;
}

