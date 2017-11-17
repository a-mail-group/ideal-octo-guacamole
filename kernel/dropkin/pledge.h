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

#define PLEDGE_STDIO     0x0001
#define PLEDGE_RPATH     0x0002
#define PLEDGE_WPATH     0x0004
#define PLEDGE_CPATH     0x0008
#define PLEDGE_DPATH     0x0010
#define PLEDGE_FATTR     0x0020
#define PLEDGE_INET      0x0040
#define PLEDGE_UNIX      0x0080
#define PLEDGE_PROT_EXEC 0x0100
#define PLEDGE_FLOCK     0x0200
#define PLEDGE_EXEC      0x0400
#define PLEDGE_SENDFD    0x0800
#define PLEDGE_RECVFD    0x1000

#define PLEDGE_UNSUPPORTED 0x40000000

int dropkin_check_pledge(u32 pledge);

#define passpledge(pledge,x) if(dropkin_check_pledge(pledge)) return x

int dropkin_abort(void);

#define E_ABORT dropkin_abort()

