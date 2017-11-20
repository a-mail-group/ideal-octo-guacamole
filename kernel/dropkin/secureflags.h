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
#include <linux/types.h>

bool dropkin_check_secureflags(u32 flags);

#define passsecflags(flags,x) if(dropkin_check_secureflags(flags)) return x

#define SECF_NO_ROOT      0x00000001
#define SECF_NO_MOUNT     0x00000002
#define SECF_NO_BLK_READ  0x00000004
#define SECF_NO_BLK_WRITE 0x00000008
#define SECF_NO_CHR_READ  0x00000010
#define SECF_NO_CHR_WRITE 0x00000020
#define SECF_NO_CHANGENET 0x00000040
#define SECF_NO_NEEDCAPS  0x00000080

