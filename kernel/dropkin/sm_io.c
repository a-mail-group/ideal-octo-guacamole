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
#include <linux/fs.h>

#include "entry_points.h"
#include "structs.h"
#include "prctl_numbers.h"
#include "macros.h"
#include "pledge.h"
#include "mls.h"
#include "util_file.h"
#include "filepac.h"

#define REQ_CPATH { passnocred(current->cred,0); passpledge(PLEDGE_CPATH, E_ABORT); return 0; }
//#define UNSUPPORTED { passnocred(current->cred,0); passpledge(PLEDGE_UNSUPPORTED, E_ABORT); return 0; }

// TODO: stash umode_t in DROPKIN_inode_t 
int  dropkin_inode_alloc_security(struct inode *inode){
	DROPKIN_inode_t *ins;
	ins = kzalloc(sizeof(DROPKIN_inode_t),GFP_KERNEL);
	if(!ins)return -ENOMEM;
	inode->i_security = ins;
	return 0;
}
void dropkin_inode_free_security(struct inode *inode){
	DROPKIN_inode_t *ins;
	ins = inode->i_security;
	if(ins)kfree(ins);
}

int dropkin_inode_permission(struct inode *inode, int mask) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	if(mask&(MAY_READ|MAY_EXEC)) passpledge(PLEDGE_RPATH|PLEDGE_WPATH, E_ABORT);
	if(mask&MAY_WRITE) passpledge(PLEDGE_WPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(inode, &isec)) passfilepac(pt,&isec,mask,-EPERM);
	//	passmlsf(pt->subject,&isec,bcast(mask&MAY_WRITE),bcast(mask&(MAY_READ|MAY_EXEC)),-EPERM);
	
	return 0;
}

int dropkin_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	return 0;
}

int dropkin_inode_mknod (struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_DPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	return 0;
}

int dropkin_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) {
	DROPKIN_inode_t isec;
	
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	/*
	 * We must also have the access rights to the file.
	 */
	if(dropkin_inode_get_dentry(old_dentry, &isec)) passfilepac(pt,&isec,0,-EPERM);
	
	return 0;
}
int dropkin_inode_unlink(struct inode *dir, struct dentry *dentry) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	if(dropkin_inode_get_dentry(dentry, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	return 0;
}
int dropkin_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name) REQ_CPATH;
int dropkin_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	return 0;
}
int dropkin_inode_rmdir(struct inode *dir, struct dentry *dentry) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	/*
	 * We must also have the access rights to the file.
	 */
	if(dropkin_inode_get_dentry(dentry, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	return 0;
}
int dropkin_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(old_dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	if(dropkin_inode_get_inode(new_dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	/*
	 * We must also have the access rights to the file.
	 */
	if(dropkin_inode_get_dentry(old_dentry, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	return 0;
}

int dropkin_inode_setattr(struct dentry *dentry, struct iattr *attr) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_FATTR, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_dentry(dentry, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EPERM);
	
	return 0;
}
int dropkin_inode_getattr(const struct path *path) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_FATTR, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_path(path, &isec)) passfilepac(pt,&isec,MAY_READ,-EPERM);
	
	return 0;
}
void dropkin_task_to_inode(struct task_struct *p, struct inode *inode) {
	DROPKIN_inode_t *ins;
	DROPKIN_credx_t *pt;
	
	passnocred(p->cred,);
	passnoino(inode,);
	
	ins = inode->i_security;
	pt = p->cred->security;
	
	dropkin_repr_as_file(pt,ins);
}

