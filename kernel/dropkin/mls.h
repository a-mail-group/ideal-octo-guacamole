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


#include "structs.h"

int dropkin_check_mls(DROPKIN_subject_t *subject,DROPKIN_subject_t *object);

#define passmls(sub,obj,x) if(dropkin_check_mls(&(sub),&(obj))) return x

int dropkin_check_mlsf(DROPKIN_subject_t *subject, DROPKIN_inode_t *object, bool read,bool write);

#define passmlsf(sub,ino,read,write,x) if(dropkin_check_mlsf(&(sub),ino,read,write)) return x
