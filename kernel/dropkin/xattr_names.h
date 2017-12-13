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
#include <linux/xattr.h>

#define FXASUF_DROPKIN "DROPKIN"

#define FXA_PREFIX        XATTR_SECURITY_PREFIX FXASUF_DROPKIN
#define FXA_MLS_READ      FXA_PREFIX "_RPR"
#define FXA_MLS_WRITE     FXA_PREFIX "_WPR"

#define FXA_TYPE_ID       XATTR_SECURITY_PREFIX "DROPKIN_TID"

