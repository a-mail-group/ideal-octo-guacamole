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
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/cred.h>
#include "structs.h"
#include "secureflags.h"
#include "macros.h"

bool dropkin_check_secureflags(u32 flags) {
	DROPKIN_credx_t *t;
	
	t = current->cred->security;
	
	return bcast(t->secure_flags&flags);
}

