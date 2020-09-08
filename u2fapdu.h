/*
 *
 * copyright 2019 the wookey project team <wookey@ssi.gouv.fr>
 *   - ryad     benadjila
 *   - arnauld  michelizza
 *   - mathieu  renard
 *   - philippe thierry
 *   - philippe trebuchet
 *
 * this package is free software; you can redistribute it and/or modify
 * it under the terms of the gnu general public license as published
 * the free software foundation; either version 3 of the license, or (at
 * ur option) any later version.
 *
 * this package is distributed in the hope that it will be useful, but without any
 * warranty; without even the implied warranty of merchantability or fitness for a
 * particular purpose. see the gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license along
 * with this package; if not, write to the free software foundation, inc., 51
 * franklin st, fifth floor, boston, ma 02110-1301 usa
 *
 */
#ifndef U2FAPDU_H_
#define U2FAPDU_H_

#include "autoconf.h"
#include "libc/types.h"

#include "libc/stdio.h"
#include "api/libu2fapdu.h"

#if CONFIG_USR_LIB_U2FAPDU_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif




#define SHORT_APDU_LC_MAX       255
#define SHORT_APDU_LE_MAX       256

#define EXTENDED_APDU_LE_MAX	65536

/* An APDU command (handling extended APDU) */
typedef struct __attribute__((packed)) {
    uint8_t extended_apdu; /* Is it a short of an extended length APDU */
    uint8_t cla;           /* Command class */
    uint8_t ins;           /* Instruction */
    uint8_t p1;            /* Parameter 1 */
    uint8_t p2;            /* Parameter 2 */
    uint16_t Lc;           /* Length of data field, Lc encoded on 16 bits since it is always < 65535 */
    uint32_t Le;           /* Expected return length, encoded on 32 bits since it is <= 65536 (so we must encode the last value) */
    uint8_t *data;         /* Data field */
} u2fapdu_cmd_t;

#define U2F_REGISTER				0x01
#define U2F_AUTHENTICATE 			0x02
#define U2F_VERSION		            0x03
#define U2F_VENDOR_SPECIFIC_MIN 	0x40
#define U2F_VENDOR_SPECIFIC_MAX 	0xbf


#define SW_NO_ERROR 				0x9000
#define SW_CONDITIONS_NOT_SATISFIED	0x6985
#define SW_WRONG_DATA				0x6A80
#define SW_WRONG_LENGTH				0x6700
#define SW_CLA_NOT_SUPPORTED		0x6E00
#define SW_INS_NOT_SUPPORTED		0x6D00

#define CHECK_ONLY				            0x07
#define ENFORCE_USER_PRESENCE_AND_SIGN	    0x03
#define DONT_ENFORCE_USER_PRESENCE_AND_SIGN	0x08

#define NO_ERROR				        0x00
#define REQUIRE_TEST_USER_PRESENCE		0x01
#define INVALID_KEY_HANDLE	        	0x02
#define WRONG_LENGTH			    	0x03

#endif /* U2FAPDU_H_ */
