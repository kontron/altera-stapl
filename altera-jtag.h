/*
 * altera-jtag.h
 *
 * altera FPGA driver
 *
 * Copyright (C) Altera Corporation 1998-2001
 * Copyright (C) 2010 NetUP Inc.
 * Copyright (C) 2010 Igor M. Liplianin <liplianin@netup.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef ALTERA_JTAG_H
#define ALTERA_JTAG_H

/* Function Prototypes */
enum altera_jtag_state {
	ILLEGAL_JTAG_STATE = -1,
	RESET = 0,
	IDLE = 1,
	DRSELECT = 2,
	DRCAPTURE = 3,
	DRSHIFT = 4,
	DREXIT1 = 5,
	DRPAUSE = 6,
	DREXIT2 = 7,
	DRUPDATE = 8,
	IRSELECT = 9,
	IRCAPTURE = 10,
	IRSHIFT = 11,
	IREXIT1 = 12,
	IRPAUSE = 13,
	IREXIT2 = 14,
	IRUPDATE = 15

};

struct altera_jtag {
	/* Global variable to store the current JTAG state */
	enum altera_jtag_state jtag_state;

	/* Store current stop-state for DR and IR scan commands */
	enum altera_jtag_state drstop_state;
	enum altera_jtag_state irstop_state;

	/* Store current padding values */
	uint32_t dr_pre;
	uint32_t dr_post;
	uint32_t ir_pre;
	uint32_t ir_post;
	uint32_t dr_length;
	uint32_t ir_length;
	uint8_t *dr_pre_data;
	uint8_t *dr_post_data;
	uint8_t *ir_pre_data;
	uint8_t *ir_post_data;
	uint8_t *dr_buffer;
	uint8_t *ir_buffer;
};

#define ALTERA_STACK_SIZE 128
#define ALTERA_MESSAGE_LENGTH 1024

int altera_jinit(struct altera_jtag *js);
int altera_set_drstop(struct altera_jtag *js, enum altera_jtag_state state);
int altera_set_irstop(struct altera_jtag *js, enum altera_jtag_state state);
int altera_set_dr_pre(struct altera_jtag *js, uint32_t count, uint32_t start_index,
				uint8_t *preamble_data);
int altera_set_ir_pre(struct altera_jtag *js, uint32_t count, uint32_t start_index,
				uint8_t *preamble_data);
int altera_set_dr_post(struct altera_jtag *js, uint32_t count, uint32_t start_index,
				uint8_t *postamble_data);
int altera_set_ir_post(struct altera_jtag *js, uint32_t count, uint32_t start_index,
				uint8_t *postamble_data);
int altera_goto_jstate(struct altera_jtag *js,
				enum altera_jtag_state state);
int altera_wait_cycles(struct altera_jtag *js, int32_t cycles,
				enum altera_jtag_state wait_state);
int altera_wait_msecs(struct altera_jtag *js, int32_t microseconds,
				enum altera_jtag_state wait_state);
int altera_irscan(struct altera_jtag *js, uint32_t count,
				uint8_t *tdi_data, uint32_t start_index);
int altera_swap_ir(struct altera_jtag *js,
				uint32_t count, uint8_t *in_data,
				uint32_t in_index, uint8_t *out_data,
				uint32_t out_index);
int altera_drscan(struct altera_jtag *js, uint32_t count,
				uint8_t *tdi_data, uint32_t start_index);
int altera_swap_dr(struct altera_jtag *js, uint32_t count,
				uint8_t *in_data, uint32_t in_index,
				uint8_t *out_data, uint32_t out_index);
void altera_free_buffers(struct altera_jtag *js);
#endif /* ALTERA_JTAG_H */
