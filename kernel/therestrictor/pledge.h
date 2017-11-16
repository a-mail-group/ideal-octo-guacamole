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

#define PLEDGE_STDIO  0x01
#define PLEDGE_RPATH  0x02
#define PLEDGE_WPATH  0x04
#define PLEDGE_CPATH  0x08
#define PLEDGE_DPATH  0x10


#define PLEDGE_UNSUPPORTED 0x40000000

int therest_check_pledge(u32 pledge);

