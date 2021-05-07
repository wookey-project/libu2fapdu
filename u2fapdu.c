/*
 *
 * Copyright 2019 The wookey project team <wookey@ssi.gouv.fr>
 *   - Ryad     Benadjila
 *   - Arnauld  Michelizza
 *   - Mathieu  Renard
 *   - Philippe Thierry
 *   - Philippe Trebuchet
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * the Free Software Foundation; either version 3 of the License, or (at
 * ur option) any later version.
 *
 * This package is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this package; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */
#include "autoconf.h"
#include "libc/types.h"
#include "libc/string.h"
#include "libc/nostd.h"
#include "u2fapdu.h"


/* Parse a command APDU (either short or extended) */
static mbed_error_t u2fapdu_parse_cmd(uint8_t *apdu_buff,
                                      uint32_t apdu_len,
                                      u2fapdu_cmd_t *apdu)
{
	/* Sanity check: minimum length is 4 (CLA + INS + P1 + P2)  */
	if((apdu_buff == NULL) || (apdu_len < 4)){
		goto err;
	}
	memset(apdu, 0, sizeof(apdu));
	/* Begin by getting CLA, INS, P1, P2 */
	apdu->cla = apdu_buff[0];
	apdu->ins = apdu_buff[1];
	apdu->p1  = apdu_buff[2];
	apdu->p2  = apdu_buff[3];
	apdu->data = NULL;
	apdu->Lc = apdu->Le = 0;
	/* Now go and parse the APDU */
	if(apdu_len == 4){
		goto end;
	}
	if(apdu_buff[4] == 0){
		/* This can be a Le=0, an extended Lc, or an extended Le */
		if(apdu_len == 5){
			/* This is definitely a Le=0, meaning 256 bytes max expected */
			apdu->Lc = 0;
			apdu->Le = SHORT_APDU_LE_MAX;
			apdu->extended_apdu = 0;
			goto end;
		}
		else if(apdu_len == 8){
			/* We have an extended Le */
			apdu->extended_apdu = 1;
			apdu->Le = (apdu_buff[5] << 8) | apdu_buff[6];
			apdu->Lc = 0;
			goto end;
		}
		else if(apdu_len >= 8) {
			/* This is an extended Lc */
			apdu->extended_apdu = 1;
			apdu->Lc = (apdu_buff[5] << 8) | apdu_buff[6];
			/* Sanity check */
			if((apdu_len != (7 + (uint32_t)apdu->Lc)) && (apdu_len != (7 + (uint32_t)apdu->Lc + 2))){
				goto err;
			}
			/* Get the data */
			apdu->data = &apdu_buff[7];
			if(apdu_len == (7 + (uint32_t)apdu->Lc + 2)){
				apdu->Le = (apdu_buff[7 + (uint32_t)apdu->Lc] << 8) | apdu_buff[7 + (uint32_t)apdu->Lc + 1];
				if(apdu->Le == 0x00){
					apdu->Le = EXTENDED_APDU_LE_MAX;
				}
			}
			goto end;
		}
		else{
			goto err;
		}
	}
	else{
		/* If we are here, this is a short APDU */
		apdu->extended_apdu = 0;
		/* Check if we have Lc or Le */
		if(apdu_len == 5){
			/* This is the case where we have Le */
			apdu->Le = apdu_buff[4];
			apdu->Lc = 0;
			if(apdu->Le == 0x00){
				apdu->Le = SHORT_APDU_LE_MAX;
			}
			goto end;
		}
		else{
			/* We have Lc */
			apdu->Lc = apdu_buff[4];
			if((apdu_len != (5 + (uint32_t)apdu->Lc)) && (apdu_len != (5 + (uint32_t)apdu->Lc + 1))){
				goto err;
			}
			apdu->data = &apdu_buff[5];
			if(apdu_len == (5 + (uint32_t)apdu->Lc + 1)){
				apdu->Le = apdu_buff[5 + (uint32_t)apdu->Lc];
				if(apdu->Le == 0x00){
					apdu->Le = SHORT_APDU_LE_MAX;
				}
			}
			goto end;
		}
	}

end:
	return MBED_ERROR_NONE;
err:
	return MBED_ERROR_INVPARAM;
}

/* Forge a response APDU. This function supports aliasing of buffers. */
static mbed_error_t u2f_apdu_forge_resp(uint8_t  *resp_buff,
                                        uint16_t *resp_len,
                                        uint8_t   sw1,
                                        uint8_t   sw2,
                                        uint8_t  *resp_data_buff,
                                        uint16_t  resp_data_buff_len)
{
	//uint8_t extended_response = 0;
	if((resp_buff == NULL) || (resp_len == NULL)){
		goto err;
	}
	if((resp_data_buff == NULL) && (resp_data_buff_len != 0)){
		goto err;
	}
	if((*resp_len) < (resp_data_buff_len + 2)){
		goto err;
	}
	*resp_len = (resp_data_buff_len + 2);

	if(resp_data_buff != NULL){
		memcpy(&resp_buff[0], resp_data_buff, resp_data_buff_len);
	}
	resp_buff[resp_data_buff_len]     = sw1;
	resp_buff[resp_data_buff_len + 1] = sw2;

	log_printf("[U2F_APDU] Forging APDU response:\n");
	log_printf("SW1=0x%x, SW2=0x%x, Le=0x%x\n", sw1, sw2, resp_data_buff_len);
#if CONFIG_USR_LIB_U2FAPDU_DEBUG
        hexdump(resp_buff, resp_data_buff_len);
#endif

	return MBED_ERROR_NONE;
err:
	return MBED_ERROR_INVPARAM;
}


static void u2fapdu_print_apdu(const u2fapdu_cmd_t *apdu __attribute__((unused)))
{
#if CONFIG_USR_LIB_U2FAPDU_DEBUG
	log_printf("CLA=0x%x, INS=0x%x, P1=0x%x, P2=0x%x\n", apdu->cla, apdu->ins, apdu->p1, apdu->p2);
	log_printf("Lc=0x%x, Le=0x%x, %s\n", apdu->Lc, apdu->Le, (apdu->extended_apdu == 1) ? "Extended APDU" : "Short APDU");

	if ((apdu->data != NULL) && (apdu->Lc != 0)) {
        hexdump(apdu->data, apdu->Lc);
	}
#endif
	return;
}

/***** Handle U2F FIDO APDU layer *****/

/*
 * TODO: we should use a context here
 */
static volatile apdu_upper_layer_cb_t apdu_callback = NULL;

/*
 * FIXME: should we not check that callback is non-NULL ?
 */
mbed_error_t u2fapdu_register_callback(apdu_upper_layer_cb_t callback)
{
        apdu_callback = callback;
        return MBED_ERROR_NONE;
}


mbed_error_t u2fapdu_handle_cmd(uint32_t  metadata __attribute__((unused)),
                                uint8_t  *apdu_buff,
                                uint16_t  apdu_len,
                                uint8_t  *resp_buff,
                                uint16_t *resp_len)
{
	u2fapdu_cmd_t apdu;
	uint16_t sw1sw2;
        mbed_error_t errcode = MBED_ERROR_INVPARAM;

        if((apdu_buff == NULL) || (resp_buff == NULL) || (resp_len == NULL)){
                errcode = MBED_ERROR_INVPARAM;
		goto err;
        }
	/* Parse the APDU */
	if ((errcode = u2fapdu_parse_cmd(apdu_buff, apdu_len, &apdu)) != MBED_ERROR_NONE) {
		/* We have an error when parsing, send an error */
	        log_printf("[U2F_APDU] %s: error when parsing APDU, SW_WRONG_LENGTH\n", __func__);
		sw1sw2 = SW_WRONG_LENGTH;
		goto send_error;
	}
	if (apdu.cla != 0x00) {
	        log_printf("[U2F_APDU] %s: CLA != 0, SW_CLA_NOT_SUPPORTED\n", __func__);
		sw1sw2 = SW_CLA_NOT_SUPPORTED;
                errcode = MBED_ERROR_UNSUPORTED_CMD;
		goto send_error;
	}
	/* Only P2 = 0 is supported for all instructions */
	if (apdu.p2 != 0x00) {
	        log_printf("[U2F_APDU] %s: P2 != 0, SW_WRONG_DATA\n", __func__);
		sw1sw2 = SW_WRONG_DATA;
                errcode = MBED_ERROR_UNSUPORTED_CMD;
		goto send_error;
	}
	if (apdu.ins == U2F_AUTHENTICATE) {
		if ((apdu.p1 != ENFORCE_USER_PRESENCE_AND_SIGN) &&
                    (apdu.p1 != CHECK_ONLY) &&
                    (apdu.p1 != DONT_ENFORCE_USER_PRESENCE_AND_SIGN)) {
	                log_printf("[U2F_APDU] %s: error in P1=0x%x (!= 0x%x or 0x%x or 0x%x), SW_WRONG_DATA\n", __func__, apdu.p1, ENFORCE_USER_PRESENCE_AND_SIGN, CHECK_ONLY, DONT_ENFORCE_USER_PRESENCE_AND_SIGN);
			sw1sw2 = SW_WRONG_DATA;
                        errcode = MBED_ERROR_UNSUPORTED_CMD;
                        goto send_error;
		}
	} else {
		if (apdu.p1 != 0x00) {
                        if((apdu.ins == U2F_REGISTER) && ((apdu.p1 != ENFORCE_USER_PRESENCE_AND_SIGN) || (apdu.p1 != CHECK_ONLY) || (apdu.p1 != DONT_ENFORCE_USER_PRESENCE_AND_SIGN))){
                            /* NOTE: some implementation wrongly use P1 != 0 for U2F_REGISTER ... In lax mode
                             * allow this!
                             */
				log_printf("[U2FAPDU] %s:warning,  P1 != 0 (= 0x%x) for U2F_REGISTER\n", __func__, apdu.p1);
				log_printf("           => we are in lax mode: ignoring this error ...\n");
                        }
                        else{
     	                    log_printf("[U2F_APDU] %s: P1 != 0, SW_WRONG_DATA\n", __func__);
  			    sw1sw2 = SW_WRONG_DATA;
                            errcode = MBED_ERROR_UNSUPORTED_CMD;
			    goto send_error;
                       }
		}
	}
	log_printf("[U2F_APDU] %s: Received an APDU:\n", __func__);
        /* print apdu is protected in non-DEBUG mode, no preproc required */
	u2fapdu_print_apdu(&apdu);
	/* Get the command */
	switch(apdu.ins) {
		case U2F_AUTHENTICATE:
		case U2F_REGISTER:
		case U2F_VERSION:
		{
			uint16_t orig_resp_len = *resp_len;
			/* Sanity check */
                        if(apdu_callback == NULL) {
                               log_printf("[U2FAPDU] invalid callback! leaving\n");
                                errcode = MBED_ERROR_INVSTATE;
				goto err;
			}
			/* Ask the upper layer with metadata formed with INS | P1 | P2 (for the upper layer) */
			int error = apdu_callback(apdu.ins | (apdu.p1 << 8) | (apdu.p2 << 16), apdu.data, apdu.Lc, resp_buff, resp_len);
			/* NOTE: we are not strict here because many implementations are not conforming, but is data out is to be expected,
			 * we should enforce Le!
			 */
			if ((*resp_len) > apdu.Le) {
				log_printf("[U2FAPDU] %s: warning, got response of len %d > Le=%d\n", __func__, *resp_len, apdu.Le);
				log_printf("           => we are in lax mode: ignoring this error ...\n");
			}
			uint16_t no_error_payload_size = *resp_len;
			*resp_len = orig_resp_len;
			switch(error){
				case NO_ERROR:{
					/* No error. Forge the response and send it back! */
					sw1sw2 = SW_NO_ERROR;
					if (u2f_apdu_forge_resp(resp_buff, resp_len, (sw1sw2 >> 8), (sw1sw2 & 0xff), resp_buff, no_error_payload_size)) {
                                                errcode = MBED_ERROR_WRERROR;
						goto err;
					}
					goto end;
				}
				case REQUIRE_TEST_USER_PRESENCE:{
					log_printf("[U2FAPDU] %s Error: REQUIRE_TEST_USER_PRESENCE/SW_CONDITIONS_NOT_SATISFIED\n", __func__);
                                        sw1sw2 = SW_CONDITIONS_NOT_SATISFIED;
                                        errcode = MBED_ERROR_INVCREDENCIALS;
					goto send_error;
				}
				case INVALID_KEY_HANDLE:{
					log_printf("[U2FAPDU] %s Error: INVALID_KEY_HANDLE/SW_WRONG_DATA\n", __func__);
					sw1sw2 = SW_WRONG_DATA;
                                        errcode = MBED_ERROR_NOTFOUND;
					goto send_error;
				}
				case WRONG_LENGTH:{
					log_printf("[U2FAPDU] %s Error: WRONG_LENGTH/SW_WRONG_LENGTH\n", __func__);
					sw1sw2 = SW_WRONG_LENGTH;
                                        errcode = MBED_ERROR_INVPARAM;
					goto send_error;
				}
				default:
					log_printf("[U2FAPDU] %s Error: unkown error!\n", __func__);
					/* Unkown error ... */
                                        errcode = MBED_ERROR_UNKNOWN;
					goto err;
			}
			break;
		}
		default: {
                        sw1sw2 = SW_INS_NOT_SUPPORTED;
                        errcode = MBED_ERROR_UNSUPORTED_CMD;
			goto send_error;
		}
	}

send_error:
	if((errcode = u2f_apdu_forge_resp(resp_buff, resp_len, (sw1sw2 >> 8), (sw1sw2 & 0xff), NULL, 0)) != MBED_ERROR_NONE){
		goto err;
	}
end:
        errcode = MBED_ERROR_NONE;
	return errcode;
err:
	return errcode;
}
