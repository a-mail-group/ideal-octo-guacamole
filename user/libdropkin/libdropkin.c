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
#include <dropkin/pledge.h>
#include <dropkin/caps.h>
#include <dropkin/secureflags.h>
#include <dropkin/isolation.h>
#include <sys/prctl.h>

// Hopefully unused PRCTL commands.
#define PRX_TR_BASE        1000
#define PRX_TR_PLEDGE      1001
#define PRX_TR_PLEDGE_NOT  1002
#define PRX_TR_ABORT       1003
#define PRX_TR_MLS_RING    1004
#define PRX_TR_ISO_ID      1005
#define PRX_TR_SET_SECFLAG 1006
#define PRX_TR_SET_CAP     1007

void pledge(unsigned int promises){
	prctl(PRX_TR_PLEDGE  ,promises,0,0,0);
}
void process_set_secure_flags(unsigned int flags){
	prctl(PRX_TR_SET_SECFLAG,flags,0,0,0);
}
void process_add_capability(unsigned int type_id, unsigned int caps){
	prctl(PRX_TR_SET_CAP ,type_id,caps,0,0);
}
void process_set_isolation(unsigned int iso_id){
	prctl(PRX_TR_ISO_ID  ,iso_id,0,0,0);
}
void process_set_ring(unsigned int mls_ring){
	prctl(PRX_TR_MLS_RING,mls_ring,0,0,0);
}

