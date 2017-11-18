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
#include "pledge.h"
#include "structs.h"


int dropkin_check_pledge(u32 pledge) {
	DROPKIN_credx_t *t;
	
	t = current->cred->security;

	if((~(t->pledge)) & pledge) return 0;
	return -1;
}

int dropkin_abort(void) {
	struct siginfo info;
	pr_warn("PLEDGE-VIOLATION: Process (pid=%d; uid=%d; gid=%d) killed!",
		(int)(current->pid),
		(int)(current->cred->uid.val),
		(int)(current->cred->gid.val)
	);
	info.si_signo = SIGABRT;
	info.si_errno = 0;
	info.si_code = SI_KERNEL;

	do_send_sig_info(SIGABRT, &info, current, true);
	return -EPERM;
}

