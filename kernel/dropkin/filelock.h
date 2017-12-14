#pragma once
/*
 * Locks for Files and Directories (not in terms of synchronization).
 *
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
#include "structs.h"

/*
 * s : no symlink() in this dir.
 * f : no create() in this dir (or, creating files not allowed).
 * d : no mkdir() in this dir.
 * n : no mknod() in this dir (also mkfifo() or AF_UNIX sockets).
 * l : no link() or rename() into this dir.
 * u : no unlink()/rmdir() in or rename() out of this dir.
 *
 * For files, directories and others:
 * a : no setattr() on this file.
 * A : no getattr() on this file.
 * x : no setxattr() on this file.
 * X : no getxattr() on this file.
 *
 * r : no unlink()/rmdir() or rename() on this file.
 * p : no link() or rename() on this file.
**/

#define LOCKFLAG_S  0x001
#define LOCKFLAG_F  0x002
#define LOCKFLAG_D  0x004
#define LOCKFLAG_N  0x008
#define LOCKFLAG_L  0x010
#define LOCKFLAG_U  0x020
#define LOCKFLAG_A  0x040
#define LOCKFLAG_AW 0x080
#define LOCKFLAG_X  0x100
#define LOCKFLAG_XW 0x200
#define LOCKFLAG_R  0x400
#define LOCKFLAG_P  0x800

/*
 * Return value:
 *    False: Access granted.
 *    True:  Access denied.
 */
bool dropkin_check_lockflags(DROPKIN_inode_t *object, int flags);

#define passfilelock(ino,flags,x) if(dropkin_check_lockflags(ino,flags)) return x

void dropkin_lockflags_import(DROPKIN_inode_t *object,const void* buffer,size_t len);

