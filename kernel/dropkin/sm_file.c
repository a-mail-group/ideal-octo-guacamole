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

int dropkin_file_lock(struct file *file, unsigned int cmd) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_FLOCK, E_ABORT);
	return 0;
}

int dropkin_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_FLOCK|PLEDGE_STDIO, E_ABORT);
	return 0;
}

int dropkin_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	return 0;
}
int dropkin_file_receive(struct file *file) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_RECVFD, E_ABORT);
	return 0;
}

int dropkin_sb_statfs(struct dentry *dentry) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	return 0;
}
int dropkin_sb_mount(const char *dev_name, const struct path *path, const char *type, unsigned long flags, void *data) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	return 0;
}
int dropkin_sb_umount(struct vfsmount *mnt, int flags) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	return 0;
}
int dropkin_sb_pivotroot(const struct path *old_path, const struct path *new_path) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	return 0;
}

