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
#include "various_consts.h"
#include "macros.h"
#include "pledge.h"
#include "mls.h"
#include "util_file.h"
#include "filepac.h"
#include "filelock.h"
#include "parsenum.h"
#include "util_mem.h"
#include "secureflags.h"

//#define REQ_CPATH { passnocred(current->cred,0); passpledge(PLEDGE_CPATH, E_ABORT); return 0; }

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
int  dropkin_inode_init_security(struct inode *inode, struct inode *dir, const struct qstr *qstr, const char **name, void **value, size_t *len){
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	u32 tid,dtid;
	
	passnocred(current->cred,-EOPNOTSUPP);
	
	pt = current->cred->security;
	
	isec.res_type_id = 0;
	dropkin_inode_get_inode(dir, &isec);
	
	tid = 0;
	dtid = cap2rti(isec.res_type_id);
	
	/*
	 * The RTI is always that of the parent directory, if any.
	 */
	tid = dtid;
	
	if (!tid) return -EOPNOTSUPP;
	
	/* TODO : Isn't that already handled by dropkin_d_instantiate() ? */
	if (inode->i_security)
		((DROPKIN_inode_t*)(inode->i_security))->res_type_id = rti2cap(tid);
	
	if (name)
		*name = "DROPKIN_TID";
	if (value && len) {
		*value = dropkin_serialize_securely(tid,len);
		if (!(*value)) return -ENOMEM;
	}
	
	return 0;
}

void dropkin_d_instantiate(struct dentry *dentry, struct inode *inode) {
	DROPKIN_inode_t *ino;
	char buffer[64];
	int rc;
	struct dentry *dp;
	
	passnoino(inode,);
	ino = inode->i_security;
	
	dp = dget(dentry);
	
	/*
	 * Load the Type-ID for the CAPSEC system.
	 */
	rc = __vfs_getxattr(dp,inode,FXA_TYPE_ID,buffer,sizeof buffer);
	if(rc>0) ino->res_type_id = rti2cap(dropkin_parse_securly(buffer,rc));
	
	/*
	 * Load the File-Padlocks.
	 */
	rc = __vfs_getxattr(dp,inode,FXA_LOCKS,buffer,sizeof buffer);
	if(rc>0) dropkin_lockflags_import(ino,buffer,rc);
	
	dput(dp);
}

void dropkin_inode_post_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags) {
	DROPKIN_inode_t *ino;
	struct inode *inode;
	
	inode = dentry->d_inode;
	if(!inode)return;
	
	passnoino(inode,);
	ino = inode->i_security;
	
	/*
	 * Load the Type-ID for the CAPSEC system.
	 */
	if(dropkin_streq(name,FXA_TYPE_ID)) {
		ino->res_type_id = rti2cap(dropkin_parse_securly(value,size));
	}
	
	/*
	 * Load the File-Padlocks.
	 */
	else if(dropkin_streq(name,FXA_LOCKS)) {
		dropkin_lockflags_import(ino,value,size);
	}
}

/* ------------------------------- The main permission checker. ---------------------------------- */

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

/* ---------------- FILE/DIR/ETC CREATE/DELETE/RENAME/LINK ------------------- */

int dropkin_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)){
		passfilepac(pt,&isec,MAY_WRITE|xMAY_DIR_INSERT,-EACCES);
		/*
		 * f : no create() in this dir (or, creating files not allowed).
		 */
		passfilelock(&isec,LOCKFLAG_F,-EACCES);
	}
	
	return 0;
}

int dropkin_inode_mknod (struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_DPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)){
		passfilepac(pt,&isec,MAY_WRITE|xMAY_DIR_INSERT,-EACCES);
		/*
		 * n : no mknod() in this dir (also mkfifo() or AF_UNIX sockets).
		 */
		passfilelock(&isec,LOCKFLAG_N,-EACCES);
	}
	
	return 0;
}

int dropkin_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) {
	DROPKIN_inode_t isec;
	
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)){
		passfilepac(pt,&isec,MAY_WRITE|xMAY_DIR_INSERT,-EACCES);
		/*
		 * l : no link() or rename() into this dir.
		 */
		passfilelock(&isec,LOCKFLAG_L,-EACCES);
	}
	
	/*
	 * We must also have the access rights to the file.
	 */
	if(dropkin_inode_get_dentry(old_dentry, &isec)){
		passfilepac(pt,&isec,xMAY_LINK,-EACCES);
		/*
		 * p : no link() or rename() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_N,-EACCES);
	}
	
	/*
	 * Possibly, ther is a file already, to be replaced. Check if we might replace it.
	 */
	if(dropkin_inode_get_dentry(dentry, &isec)){
		passfilepac(pt,&isec,xMAY_DELETE,-EACCES);
		/*
		 * r : no unlink()/rmdir() or rename() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_R,-EACCES);
	}
	
	return 0;
}
int dropkin_inode_unlink(struct inode *dir, struct dentry *dentry) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)){
		passfilepac(pt,&isec,MAY_WRITE|xMAY_DIR_REMOVE,-EACCES);
		/*
		 * u : no unlink()/rmdir() in or rename() out of this dir.
		 */
		passfilelock(&isec,LOCKFLAG_U,-EACCES);
	}
	
	if(dropkin_inode_get_dentry(dentry, &isec)){
		passfilepac(pt,&isec,xMAY_DELETE,-EACCES);
		/*
		 * r : no unlink()/rmdir() or rename() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_R,-EACCES);
	}
	
	return 0;
}

int dropkin_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	/*
	 * If we want to create a Symlink, we need to be able to write to the directory.
	 */
	if(dropkin_inode_get_inode(dir, &isec)){
		passfilepac(pt,&isec,MAY_WRITE|xMAY_DIR_INSERT,-EACCES);
		/*
		 * s : no symlink() in this dir.
		 */
		passfilelock(&isec,LOCKFLAG_S,-EACCES);
	}
	
	/*
	 * Possibly, ther is a file already, to be replaced. Check if we might replace it.
	 */
	if(dropkin_inode_get_dentry(dentry, &isec)){
		passfilepac(pt,&isec,xMAY_DELETE,-EACCES);
		/*
		 * r : no unlink()/rmdir() or rename() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_R,-EACCES);
	}
	
	return 0;
}

int dropkin_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)){
		passfilepac(pt,&isec,MAY_WRITE|xMAY_DIR_INSERT,-EACCES);
		/*
		 * d : no mkdir() in this dir.
		 */
		passfilelock(&isec,LOCKFLAG_D,-EACCES);
	}
	
	return 0;
}
int dropkin_inode_rmdir(struct inode *dir, struct dentry *dentry) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(dir, &isec)){
		passfilepac(pt,&isec,MAY_WRITE|xMAY_DIR_REMOVE,-EACCES);
		/*
		 * u : no unlink()/rmdir() in or rename() out of this dir.
		 */
		passfilelock(&isec,LOCKFLAG_U,-EACCES);
	}
	
	/*
	 * We must also have the access rights to the file.
	 */
	if(dropkin_inode_get_dentry(dentry, &isec)){
		passfilepac(pt,&isec,xMAY_DELETE,-EACCES);
		/*
		 * r : no unlink()/rmdir() or rename() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_R,-EACCES);
	}
	
	return 0;
}
int dropkin_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_CPATH, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_inode(old_dir, &isec)){
		passfilepac(pt,&isec,MAY_WRITE|xMAY_DIR_REMOVE,-EACCES);
		/*
		 * u : no unlink()/rmdir() in or rename() out of this dir.
		 */
		passfilelock(&isec,LOCKFLAG_U,-EACCES);
	}
	
	if(dropkin_inode_get_inode(new_dir, &isec)){
		passfilepac(pt,&isec,MAY_WRITE|xMAY_DIR_INSERT,-EACCES);
		/*
		 * l : no link() or rename() into this dir.
		 */
		passfilelock(&isec,LOCKFLAG_L,-EACCES);
	}
	
	/*
	 * We must also have the access rights to the file.
	 */
	if(dropkin_inode_get_dentry(old_dentry, &isec)){
		passfilepac(pt,&isec,xMAY_RENAME,-EACCES);
		/*
		 * p : no link() or rename() on this file.
		 * r : no unlink()/rmdir() or rename() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_P|LOCKFLAG_R,-EACCES);
	}
	
	/*
	 * Possibly, ther is a file already, to be replaced. Check if we might replace it.
	 */
	if(dropkin_inode_get_dentry(new_dentry, &isec)){
		passfilepac(pt,&isec,xMAY_DELETE,-EACCES);
		/*
		 * r : no unlink()/rmdir() or rename() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_R,-EACCES);
	}
	
	return 0;
}

/* --------------------------- PROC-FS TASK-TO-FILE ------------------------------ */

void dropkin_task_to_inode(struct task_struct *p, struct inode *inode) {
	DROPKIN_inode_t *ins;
	DROPKIN_credx_t *pt;
	
	passnocred(p->cred,);
	passnoino(inode,);
	
	ins = inode->i_security;
	pt = p->cred->security;
	
	dropkin_repr_as_file(pt,ins);
}

/* --------------------------------- ATTR -----------------------------------*/

int dropkin_inode_setattr(struct dentry *dentry, struct iattr *attr) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_FATTR, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_dentry(dentry, &isec)) {
		passfilepac(pt,&isec,MAY_WRITE,-EACCES);
		/*
		 * a : no setattr() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_A,-EACCES);
	}
	
	return 0;
}
int dropkin_inode_getattr(const struct path *path) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_FATTR, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_path(path, &isec)) {
		passfilepac(pt,&isec,MAY_READ,-EACCES);
		/*
		 * A : no getattr() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_AW,-EACCES);
	}
	
	return 0;
}


/* ----------------------------- XATTR --------------------------------*/

int  dropkin_inode_setxattr(struct dentry *dentry, const char *name,const void *value, size_t size, int flags) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_FATTR, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_dentry(dentry, &isec)){
		passfilepac(pt,&isec,MAY_WRITE,-EACCES);
		/*
		 * x : no setxattr() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_X,-EACCES);
	}
	
	return 0;
}
int  dropkin_inode_removexattr(struct dentry *dentry, const char *name) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_FATTR, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_dentry(dentry, &isec)){
		passfilepac(pt,&isec,MAY_WRITE,-EACCES);
		/*
		 * x : no setxattr() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_X,-EACCES);
	}
	
	return 0;
}
int  dropkin_inode_getxattr(struct dentry *dentry, const char *name) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_FATTR, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_dentry(dentry, &isec)){
		passfilepac(pt,&isec,MAY_READ,-EACCES);
		/*
		 * X : no getxattr() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_XW,-EACCES);
	}
	
	return 0;
}
int  dropkin_inode_listxattr(struct dentry *dentry) {
	DROPKIN_inode_t isec;
	DROPKIN_credx_t *pt;
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_FATTR, E_ABORT);
	
	pt = current->cred->security;
	
	if(dropkin_inode_get_dentry(dentry, &isec)){
		passfilepac(pt,&isec,MAY_READ,-EACCES);
		/*
		 * X : no getxattr() on this file.
		 */
		passfilelock(&isec,LOCKFLAG_XW,-EACCES);
	}
	
	return 0;
}


