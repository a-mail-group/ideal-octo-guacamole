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
#include "xattr_names.h"

#include "entry_points.h"
#include "structs.h"
#include "prctl_numbers.h"
#include "macros.h"
#include "pledge.h"
#include "mls.h"
#include "util_file.h"
#include "filepac.h"
#include "parsenum.h"
#include "util_mem.h"
#include "secureflags.h"

#define REQ_CPATH { passnocred(current->cred,0); passpledge(PLEDGE_CPATH, E_ABORT); return 0; }

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
	u32 secf;
	passnocred(current->cred,0);
	
	if(mask&(MAY_READ|MAY_EXEC)) passpledge(PLEDGE_RPATH|PLEDGE_WPATH, E_ABORT);
	if(mask&MAY_WRITE) passpledge(PLEDGE_WPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(inode, &isec)) passfilepac(pt,&isec,mask,-EACCES);
	
	secf = 0;
	
	if(mask&(MAY_READ|MAY_EXEC)) secf |= (SECF_NO_BLK_READ |SECF_NO_CHR_READ );
	if(mask&MAY_WRITE)           secf |= (SECF_NO_BLK_WRITE|SECF_NO_CHR_WRITE);
	
#define SECF_NO_BLK (SECF_NO_BLK_READ|SECF_NO_BLK_WRITE)
#define SECF_NO_CHR (SECF_NO_CHR_READ|SECF_NO_CHR_WRITE)
	
	switch(((inode->i_mode)>>12)&15) {
	caseof(DT_BLK, passsecflags(secf&SECF_NO_BLK,-EACCES) );
	caseof(DT_CHR, passsecflags(secf&SECF_NO_CHR,-EACCES) );
	}
	
	return 0;
}

int dropkin_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	return 0;
}

int dropkin_inode_mknod (struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_DPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	return 0;
}

int dropkin_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) {
	DROPKIN_inode_t isec;
	
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	/*
	 * We must also have the access rights to the file.
	 */
	if(dropkin_inode_get_dentry(old_dentry, &isec)) passfilepac(pt,&isec,0,-EACCES);
	
	return 0;
}
int dropkin_inode_unlink(struct inode *dir, struct dentry *dentry) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	if(dropkin_inode_get_dentry(dentry, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	return 0;
}
int dropkin_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name) REQ_CPATH;
int dropkin_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	return 0;
}
int dropkin_inode_rmdir(struct inode *dir, struct dentry *dentry) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	/*
	 * We must also have the access rights to the file.
	 */
	if(dropkin_inode_get_dentry(dentry, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	return 0;
}
int dropkin_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(old_dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	if(dropkin_inode_get_inode(new_dir, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	/*
	 * We must also have the access rights to the file.
	 */
	if(dropkin_inode_get_dentry(old_dentry, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	return 0;
}

int dropkin_inode_setattr(struct dentry *dentry, struct iattr *attr) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_FATTR, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_dentry(dentry, &isec)) passfilepac(pt,&isec,MAY_WRITE,-EACCES);
	
	return 0;
}
int dropkin_inode_getattr(const struct path *path) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_FATTR, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_path(path, &isec)) passfilepac(pt,&isec,MAY_READ,-EACCES);
	
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

int dropkin_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc) {
	DROPKIN_inode_t *ins;
	u32 result;
	size_t res;
	passnoino(inode,-EOPNOTSUPP);
	
	ins = inode->i_security;
	
	if(dropkin_streq(name,FXA_MLS_WRITE)) {
		result = ins->mls.write_pr;
	} else if(dropkin_streq(name,FXA_MLS_READ)) {
		if(!ins->is_mls_read) return -EOPNOTSUPP;
		result = ins->mls.read_pr;
	} else {
		return -EOPNOTSUPP;
	}
	
	if(alloc) {
		*buffer = dropkin_serialize_securely(result,&res);
		if(!*buffer) return -ENOMEM;
		return (int)res;
	}
	
	return dropkin_decimal_length(result);
}
int dropkin_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags) {
	u32 parsed;
	DROPKIN_inode_t *ins;
	passnoino(inode,0);
	
	ins = inode->i_security;
	
	parsed = dropkin_parse_securly(value, size);
	if(dropkin_streq(name,FXA_MLS_WRITE)) {
		ins->mls.write_pr = parsed;
	} else if(dropkin_streq(name,FXA_MLS_READ)) {
		ins->mls.read_pr = parsed;
		ins->is_mls_read = true;
	}
	
	return 0;
}
int dropkin_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size) {
	int len = sizeof(FXA_PREFIX);
	if(buffer && (len<=buffer_size)) dropkin_mcopy(buffer,FXA_PREFIX,len);
	return len;
}

