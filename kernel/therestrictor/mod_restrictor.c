/*
 * The Restrictor
 *
 *  Copyright (C) 2017 Simon Schmidt
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2,
 *      as published by the Free Software Foundation.
 */
//

#include "entry_points.h"


static struct security_hook_list therest_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(cred_alloc_blank, therest_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free       , therest_cred_free       ),
	LSM_HOOK_INIT(task_prctl      , therest_task_prctl      ),
	
};

static __init int trest_lsm_init(void) {
	//printk(KERN_ALERT "THE RESTRICTOR\n")
	//if(!security_module_enable("therest")) panic("THE RESTRICTOR");
	//if(!security_module_enable("therest")) return 0;
	security_add_hooks(therest_hooks, ARRAY_SIZE(therest_hooks), "therest");
	panic("THE RESTRICTOR");
	return 0;
}

security_initcall(trest_lsm_init);
