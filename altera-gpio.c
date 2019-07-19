/*
 * altera-gpio.c
 *
 * Userspace GPIO frontend
 *
 * Copyright (C) Altera Corporation 1998-2001
 * Copyright (C) 2016-2019 Kontron Europe GmbH
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

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <gpiod.h>
#include "altera.h"

#ifndef VERSION
#define VERSION "unrel"
#endif

enum gpio_pin {
	GPIO_TCK = 0,
	GPIO_TDO,
	GPIO_TDI,
	GPIO_TMS
};

static struct gpiod_line *gpio_lines[4] = {0,0,0,0};
static int gpio_state[4] = {-1,-1,-1,-1};
static char *gpio_names = NULL;
static char *gpio_desc = NULL;
bool verbose = false;
bool trace = false;

static void gpio_set_value(int gpio, int value)
{
	struct gpiod_line *line = gpio_lines[gpio];

	if (gpio_state[gpio] != value) {
		gpiod_line_set_value(line, value);
		gpio_state[gpio] = value;
	}
}

static int gpio_get_value(int gpio)
{
	return gpiod_line_get_value(gpio_lines[gpio]);
}

static int gpio_autodetect_lines(void)
{
	static const char *names[4][4] = {
		[GPIO_TCK] = { "TCK", "Tck", "tck", NULL },
		[GPIO_TMS] = { "TMS", "Tms", "tms", NULL },
		[GPIO_TDO] = { "TDO", "Tdo", "tdo", NULL },
		[GPIO_TDI] = { "TDI", "Tdi", "tdi", NULL }
	};
	int i;

	if (verbose) {
		printf("Trying to autodetect the GPIO lines.\n");
	}

	for (i = 0; i < 4; i++) {
		const char **name = names[i];
		struct gpiod_line *line;
		bool found = false;
		while (*name && !found) {
			line = gpiod_line_find(*name);
			if (line) {
				found = true;
			}
			name++;
		}

		if (!found) {
			fprintf(stderr, "Could not find GPIO for pin '%s'\n",
					names[i][0]);
			return 1;
		}

		if (verbose) {
			printf("Found GPIO for pin '%s' at chip %s at offset %d\n",
					names[i][0],
					gpiod_chip_name(gpiod_line_get_chip(line)),
					gpiod_line_offset(line));
		}

		gpio_lines[i] = line;
	}

	return 0;
}

static int initialize_jtag_hardware()
{
	int ret;
	struct gpiod_line *line;
	int i;

	/* auto-detect */
	if (!gpio_names && !gpio_desc) {
		ret = gpio_autodetect_lines();
		if (ret) {
			return ret;
		}
	} else if (gpio_names) {
		char *saveptr;
		char *name = strtok_r(gpio_names, ":", &saveptr);
		i = 0;
		while (name && i < 4) {
			line = gpiod_line_find(name);
			if (!line) {
				fprintf(stderr, "Could not find GPIO '%s'\n", name);
				return 1;
			}

			if (verbose) {
				printf("Found GPIO for pin '%s' at chip %s at offset %d\n",
						name,
						gpiod_chip_name(gpiod_line_get_chip(line)),
						gpiod_line_offset(line));
			}
			gpio_lines[i++] = line;
			name = strtok_r(NULL, ":", &saveptr);
		}

		if (i != 4) {
			fprintf(stderr, "You have to specify exactly 4 GPIOs\n");
			return 1;
		}
	} else if (gpio_desc) {
		char *saveptr, *saveptr2;
		char *desc = strtok_r(gpio_desc, ":", &saveptr);
		i = 0;
		while (desc && i < 4) {
			char *chip = strtok_r(desc, ",", &saveptr2);
			char *offset_str = strtok_r(NULL, ",", &saveptr2);
			unsigned int offset;

			if (!chip || !offset_str) {
				fprintf(stderr, "Invalid format for -G option\n");
				return 1;
			}

			offset = strtoul(offset_str, NULL, 10);

			line = gpiod_line_get(chip, offset);
			if (!line) {
				fprintf(stderr, "Could not find GPIO at offset %d on chip '%s'\n",
						offset, chip);
				return 1;
			}

			if (verbose) {
				printf("Found GPIO for '%s,%s' at chip %s at offset %d\n",
						chip, offset_str,
						gpiod_chip_name(gpiod_line_get_chip(line)),
						gpiod_line_offset(line));
			}
			gpio_lines[i++] = line;
			desc = strtok_r(NULL, ":", &saveptr);
		}

		if (i != 4) {
			fprintf(stderr, "You have to specify exactly 4 GPIOs\n");
			return 1;
		}
	}

	for (i = 0; i < 4; i++) {
		struct gpiod_line *line = gpio_lines[i];
		if (i == GPIO_TDO) {
			ret = gpiod_line_request_input(line, "altera-stapl");
		} else {
			ret = gpiod_line_request_output(line, "altera-stapl", 0);
		}
		if (ret) {
			fprintf(stderr, "Could not request GPIO line %d\n", i);
			return ret;
		}
	}
	return 0;
}

static void close_jtag_hardware()
{
	int i;
	for (i = 0; i < 4; i++) {
		gpiod_line_release(gpio_lines[i]);
	}
}

int altera_jtag_io(int tms, int tdi, int read_tdo)
{
	int tdo = 0;

	gpio_set_value(GPIO_TMS, tms);
	gpio_set_value(GPIO_TDI, tdi);
	gpio_set_value(GPIO_TCK, 0);
	if (read_tdo)
	{
		tdo = gpio_get_value(GPIO_TDO);
	}
	gpio_set_value(GPIO_TCK, 1);
	gpio_set_value(GPIO_TCK, 0);

	return (tdo);
}

void altera_message(char *message_text)
{
	printf("%s\n", message_text);
	fflush(stdout);
}

void altera_export_int(char *key, int32_t value)
{
}

void altera_export_bool_array(char *key, uint8_t *data, int32_t count)
{
}

static const char *error_text[] = {
	[ALTERA_SUCCESS]           = "success",
	[ALTERA_STACK_OVERFLOW]    = "stack overflow",
	[ALTERA_OUT_OF_MEMORY]     = "out of memory",
	[ALTERA_BOUNDS_ERROR]      = "bounds error",
	[ALTERA_IO_ERROR]          = "file access error",
	[ALTERA_CRC_ERROR]         = "CRC mismatch",
	[ALTERA_ACTION_NOT_FOUND]  = "action not found",
	[ALTERA_ILLEGAL_OPCODE]    = "illegal instruction code",
	[ALTERA_UNEXPECTED_END]    = "unexpected end of file",
	[ALTERA_INTERNAL_ERROR]    = "internal error",
};

static const char *exit_text_jam_v0_1[] = {
	[0] = "Success",
	[1] = "Illegal initialization values",
	[2] = "Unrecognized device",
	[3] = "Device revision is not supported",
	[4] = "Device programming failure",
	[5] = "Device is not blank",
	[6] = "Device verify failure",
	[7] = "SRAM configuration failure",
};

static const char *exit_text_jam_v2[] = {
	[0]  = "Success",
	[1]  = "Checking chain failure",
	[2]  = "Reading IDCODE failure",
	[3]  = "Reading USERCODE failure",
	[4]  = "Reading UESCODE failure",
	[5]  = "Entering ISP failure",
	[6]  = "Unrecognized device",
	[7]  = "Device revision is not supported",
	[8]  = "Erase failure",
	[9]  = "Device is not blank",
	[10] = "Device programming failure",
	[11] = "Device verify failure",
	[12] = "Read failure",
	[13] = "Calculating checksum failure",
	[14] = "Setting security bit failure",
	[15] = "Querying security bit failure",
	[16] = "Exiting ISP failure",
	[17] = "Performing system test failure",
};
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

void usage(const char *progname)
{
	fprintf(stderr,
			"Jam STAPL ByteCode Player Version %s\n"
			"\n"
			"usage: %s [options] <jbc-file>\n"
			"\n"
			"Options:\n"
			"    -h          : show help message\n"
			"    -v          : show verbose messages\n"
			"    -t          : show trace messages\n"
			"    -i          : show file info only - does not execute any action\n"
			"    -a<action>  : specify an action name (Jam STAPL)\n"
			"    -d<var=val> : initialize variable to specified value (Jam 1.1)\n"
			"    -d<proc=1>  : enable optional procedure (Jam STAPL)\n"
			"    -d<proc=0>  : disable recommended procedure (Jam STAPL)\n"
			"    -r          : don't reset JTAG TAP after use\n"
			"    -g<gpios>   : set GPIOs by their names, see below\n"
			"    -G<gpios>   : set GPIOs by chip and offset, see below\n"
			"\n"
			"GPIO pin names are given in the following format:\n"
			"    <TCK>:<TDO>:<TDI>:<TMS>, where each part might be:\n"
			" - A name of the GPIO line, eg. 'TCK', (use -g)\n"
			" - or a tuple 'gpio_chip_name,line_offset' (use -G)\n"
			"Both options may be omitted, in this case the tools tries to\n"
			"automatically detect the correct GPIOs.\n",
			VERSION, progname);
}

int main(int argc, char **argv)
{
	int error;
	int opt;
	char *filename = NULL;
	char *action = NULL;
	bool execute_program = true;
	struct altera_varinit *init_list = NULL, *init_list_tail = NULL;
	FILE *fp;
	unsigned char *file_buffer;
	off_t file_length;

	while ((opt = getopt(argc, argv, "hvia:d:rg:G:Vt")) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0]);
				return EXIT_SUCCESS;
			case 'v':
				verbose = true;
				break;
			case 'i':
				verbose = true;
				execute_program = false;
				break;
			case 'a':
				action = optarg;
				break;
			case 'd':
			{
				char *name = optarg;
				char *value_str = strchr(name, '=');

				if (name && value_str) {
					struct altera_varinit *varinit;
					uint32_t value;
					*(value_str++) = '\0';
					value = strtoul(value_str, NULL, 0);

					varinit = alloca(sizeof(struct altera_varinit));
					varinit->name = name;
					varinit->value = value;
					varinit->next = NULL;

					if (!init_list) {
						init_list = varinit;
					}
					if (init_list_tail) {
						init_list_tail->next = varinit;
					}
					init_list_tail = varinit;
				}
			} break;
			case 'r':
				break;
			case 'g':
				gpio_names = optarg;
				gpio_desc = NULL;
				break;
			case 'G':
				gpio_names = NULL;
				gpio_desc = optarg;
				break;
			case 'V':
				printf("%s\n", VERSION);
				return EXIT_SUCCESS;
			case 't':
				trace = true;
				break;
			default:
				usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	filename = argv[optind];
	if (!filename) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (execute_program) {
		error = initialize_jtag_hardware();

		if (error) {
			fprintf(stderr, "Error: can't get GPIO pins\n");
			return EXIT_FAILURE;
		}
	}

	fp = fopen(filename, "rb");
	if (!fp) {
		fprintf(stderr, "Error: can't open file '%s'\n", filename);
		return EXIT_FAILURE;
	}

	/* get length of file */
	fseek(fp, 0, SEEK_END);
	file_length = ftello(fp);
	rewind(fp);

	/* Read entire file into a buffer */
	file_buffer = malloc(file_length);

	if (!file_buffer) {
		fprintf(stderr, "Error: could not allocate memory\n");
		return EXIT_FAILURE;
	}

	if (fread(file_buffer, 1, file_length, fp) != file_length) {
		fprintf(stderr, "Error reading file '%s'\n", filename);
		return EXIT_FAILURE;
	}

	fclose(fp);

	/* Check CRC */
	error = altera_check_crc(file_buffer, file_length);

	if (error == ALTERA_CRC_ERROR) {
		fprintf(stderr, "Error: CRC mismatch.\n");
		return EXIT_FAILURE;
	} else if (error == ALTERA_IO_ERROR) {
		fprintf(stderr, "Error: File format is not recognized.\n");
		return EXIT_FAILURE;
	} else if (error != 0) {
		fprintf(stderr, "Error: Internal error (%d).\n", error);
		return EXIT_FAILURE;
	}

	/* Display file format version */
	if (verbose) {
		int format_version;
		int action_count;
		int procedure_count;
		char key[33] = {0};
		char value[257] = {0};
		int32_t offset = 0;

		altera_get_file_info(file_buffer, file_length,
			&format_version, &action_count, &procedure_count);

		printf("File format is %s ByteCode format\n",
			(format_version == 2) ? "Jam STAPL" : "pre-standardized Jam 1.1");

		/* Dump out NOTE fields */
		while (altera_get_note(file_buffer, file_length,
					&offset, key, value, 256) == 0) {
			printf("NOTE '%s' = '%s'\n", key, value);
		}

		/* Dump the action table */
		if (format_version == 2 && action_count > 0) {
			int i;
			printf("\nActions available in this file:\n");

			for (i = 0; i < action_count; i++) {
				char *action_name = NULL;
				char *description = NULL;
				struct altera_procinfo *procedure_list = NULL;
				struct altera_procinfo *procptr;

				altera_get_act_info(file_buffer, file_length,
					i, &action_name, &description, &procedure_list);

				if (description) {
					printf("%s '%s'\n", action_name, description);
				} else {
					printf("%s\n", action_name);
				}

				procptr = procedure_list;
				while (procptr) {
					if (procptr->attrs) {
						printf("    %s (%s)\n", procptr->name,
								(procptr->attrs == 1) ? "optional" : "recommended");
					}
					procedure_list = procptr->next;
					free(procptr);
					procptr = procedure_list;
				}
			}

			/* add a blank line before execution messages */
			if (execute_program) {
				printf("\n");
			}
		}
	}

	/* Execute the Jam STAPL ByteCode program */
	if (execute_program) {
		int32_t error_address;
		int exit_code;
		int format_version;
		time_t start_time;
		time_t end_time;
		int exec_result;

		time(&start_time);
		exec_result = altera_execute(file_buffer, file_length, action,
			init_list, &error_address, &exit_code, &format_version);
		time(&end_time);

		if (exec_result == ALTERA_SUCCESS) {
			const char *exit_string = "Unknown exit code";
			if (format_version == 2) {
				if (exit_code < ARRAY_SIZE(exit_text_jam_v2)) {
					exit_string = exit_text_jam_v2[exit_code];
				}
			} else {
				if (exit_code < ARRAY_SIZE(exit_text_jam_v0_1)) {
					exit_string = exit_text_jam_v0_1[exit_code];
				}
			}

			if (exit_code != 0) {
				error = 2;
			}

			printf("Exit code = %d... %s\n", exit_code, exit_string);
		} else if ((format_version == 2) && (exec_result == ALTERA_ACTION_NOT_FOUND)) {
			if (!action) {
				printf("Error: no action specified for Jam STAPL file.\n");
				error = 5;
			} else {
				printf("Error: action '%s' is not supported for this Jam STAPL file.\n", action);
				error = 6;
			}
		} else if (exec_result < ALTERA_MAX_ERROR) {
			printf("Error at address %d: %s. Aborting...\n",
					error_address, error_text[exec_result]);
			error = 99;
		} else {
			printf("Unknown error code (%d)\n", exec_result);
			error = 100;
		}

		/* Print elapsed time */
		if (verbose) {
			printf("Program took %f seconds to execute.\n",
					difftime(end_time, start_time));
		}
	}

	if (execute_program) {
		close_jtag_hardware();
	}
	free(file_buffer);

	return error;
}

