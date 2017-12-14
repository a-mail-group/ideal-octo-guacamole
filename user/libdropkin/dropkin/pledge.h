/*
 *  Copyright (C) 2017 Simon Schmidt
 *
 *	This code is public domain; you can redistribute it and/or modify
 *	it under the terms of the Creative Commons "CC0" license. See LICENSE.CC0
 *	or <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 *	Alternatively, you can use this software under the following terms (zlib-license):
 *	
 *	This software is provided 'as-is', without any express or implied
 *	warranty. In no event will the authors be held liable for any damages
 *	arising from the use of this software.
 *
 *	Permission is granted to anyone to use this software for any purpose,
 *	including commercial applications, and to alter it and redistribute it
 *	freely, subject to the following restrictions:
 *
 *	1. The origin of this software must not be misrepresented; you must not
 *	   claim that you wrote the original software. If you use this software
 *	   in a product, an acknowledgment in the product documentation would be
 *	   appreciated but is not required.
 *	2. Altered source versions must be plainly marked as such, and must not be
 *	   misrepresented as being the original software.
 *	3. This notice may not be removed or altered from any source distribution.
**/
#pragma once

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
#define PLEDGE_UDPDNS    0x2000

void pledge(unsigned int promises);

