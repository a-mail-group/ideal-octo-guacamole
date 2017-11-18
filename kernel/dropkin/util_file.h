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

#include <linux/fs.h>
#include "structs.h"

bool dropkin_inode_get_inode(const struct inode *inode, DROPKIN_inode_t *ins);
bool dropkin_inode_get_dentry(const struct dentry *dentry, DROPKIN_inode_t *ins);
bool dropkin_inode_get_path(const struct path *path, DROPKIN_inode_t *ins);

