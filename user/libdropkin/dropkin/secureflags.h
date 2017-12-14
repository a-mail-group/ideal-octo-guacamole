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

#define SECF_NO_ROOT       0x00000001
#define SECF_NO_MOUNT      0x00000002
#define SECF_NO_BLK_READ   0x00000004
#define SECF_NO_BLK_WRITE  0x00000008
#define SECF_NO_CHR_READ   0x00000010
#define SECF_NO_CHR_WRITE  0x00000020
#define SECF_NO_CHANGENET  0x00000040
#define SECF_NEEDCAPS      0x00000080
#define SECF_RESPECT_LOCKS 0x00000100

void process_set_secure_flags(unsigned int flags);

