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

/* This file is used for all kinds of Constants, that have no home yet. */

/*
 * These constants are mean't as both internal representation, as well as Interface to the userspace.
 * They are inspired by the unix access rights and are completed by the APPEND-right.
 *
 * NOTE THAT these constants are accidentially identical to MAY_EXEC, MAY_WRITE, MAY_READ, MAY_APPEND etc.
**/
#define CAP_EXEC   1
#define CAP_WRITE  2
#define CAP_READ   4
#define CAP_APPEND 8

