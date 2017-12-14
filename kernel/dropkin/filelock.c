/*
 * File <=> Process Access Control.
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
#include "filelock.h"
#include "secureflags.h"
#include "macros.h"

bool dropkin_check_lockflags(DROPKIN_inode_t *object, int flags) {
	if(dropkin_check_secureflags(SECF_RESPECT_LOCKS)) {
		if(object->lockflags&flags) return true;
	}
	return false;
}

void dropkin_lockflags_import(DROPKIN_inode_t *object,const void* buffer,size_t len){
	const char *chs = buffer;
	object->lockflags = 0;
	for(;len>0;len--,chs++){
		switch(*chs){
		caseof('s', object->lockflags |= LOCKFLAG_S  );
		caseof('f', object->lockflags |= LOCKFLAG_F  );
		caseof('d', object->lockflags |= LOCKFLAG_D  );
		caseof('n', object->lockflags |= LOCKFLAG_N  );
		caseof('l', object->lockflags |= LOCKFLAG_L  );
		caseof('u', object->lockflags |= LOCKFLAG_U  );
		
		caseof('a', object->lockflags |= LOCKFLAG_A  );
		caseof('A', object->lockflags |= LOCKFLAG_AW );
		caseof('x', object->lockflags |= LOCKFLAG_X  );
		caseof('X', object->lockflags |= LOCKFLAG_XW );
		}
	}
}

