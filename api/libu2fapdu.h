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
#ifndef LIBU2FAPDU_H_
#define LIBU2FAPDU_H_

#include "autoconf.h"
#include "libc/types.h"

/*
 * Callback that need to be called to handle upper layer treatment
 * (effective FIDO cryptographic handling)
 * TODO: should we not call this type u2fapdu_fido_backend_cb_t to understand
 *       that this call the effective FIDO backend ?
 */
typedef mbed_error_t (*apdu_upper_layer_cb_t)(uint32_t  metadata,
                                     const uint8_t  *msg,
                                     uint16_t  len_in,
                                     uint8_t  *resp,
                                     uint16_t *len_out);

/*
 * register the above callback against the U2FAPDU library
 */
mbed_error_t u2fapdu_register_callback(apdu_upper_layer_cb_t callback);

/*
 * Handle APDU command: should be executed by the below (CTAP1, U2F) stack
 * in order to decode and execute APDU commands received by the CTAP layer in
 * the libctap library.
 * This function has to be registered as a callback to the libctap library.
 */
mbed_error_t u2fapdu_handle_cmd(uint32_t metadata,
                                uint8_t *apdu_buff,
                                uint16_t apdu_len,
                                uint8_t *resp_buff,
                                uint16_t *rep_len);



#endif/*!LIBU2FAPDU_H_*/
