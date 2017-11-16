#pragma once
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
#include <linux/lsm_hooks.h>

int therest_cred_alloc_blank(struct cred *cred, gfp_t gfp);
void therest_cred_free (struct cred *cred);

int therest_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

int therest_inode_permission(struct inode *inode, int mask);
int therest_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode);
int therest_inode_mknod (struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev);

int therest_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);
int therest_inode_unlink(struct inode *dir, struct dentry *dentry);
int therest_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name);
int therest_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode);
int therest_inode_rmdir(struct inode *dir, struct dentry *dentry);
int therest_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry);

//
