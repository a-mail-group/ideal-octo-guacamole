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
#include "util_file.h"

static bool dropkin_copy_Dinode(DROPKIN_inode_t *src,DROPKIN_inode_t *ins) {
	if(!src)return false;
	*ins=*src;
	return true;
}
bool dropkin_inode_get_inode(const struct inode *inode, DROPKIN_inode_t *ins)
{
	if(!inode)return false;
	return dropkin_copy_Dinode((DROPKIN_inode_t*)(inode->i_security),ins);
}
bool dropkin_inode_get_dentry(const struct dentry *dentry, DROPKIN_inode_t *ins)
{
	if(!dentry)return false;
	return dropkin_inode_get_inode(dentry->d_inode,ins);
}
bool dropkin_inode_get_path(const struct path *path, DROPKIN_inode_t *ins)
{
	if(!path)return false;
	return dropkin_inode_get_dentry(path->dentry,ins);
}

