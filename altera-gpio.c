/*
 * altera-gpio.c
 *
 * Userspace GPIO frontend
 *
 * Copyright (C) Altera Corporation 1998-2001
 * Copyright (C) 2016 Kontron Europe GmbH
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
int gpio_pins[4] = {0,0,0,0};
int gpio_fds[4] = {0,0,0,0};
int gpio_state[4] = {-1,-1,-1,-1};

int jtag_hardware_initialized = 0;

int verbose = 0;

#define GPIO_PATH "/sys/class/gpio/"
#define GPIO_EXPORT_PATH GPIO_PATH "export"
#define GPIO_UNEXPORT_PATH GPIO_PATH "unexport"

static int gpio_export(int gpionum, int export)
{
	char *path;
	FILE *f;

	if (export) {
		path = GPIO_EXPORT_PATH;
	} else {
		path = GPIO_UNEXPORT_PATH;
	}

	f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "Could not open gpio path %s\n", path);
		return 0;
	}

	fprintf(f, "%d", gpionum);
	fclose(f);

	return 1;
}

static int gpio_direction(int gpionum, int out)
{
	char path[64];
	FILE *f;

	snprintf(path, sizeof(path)-1, "%s/gpio%d/direction", GPIO_PATH, gpionum);

	f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "Could not open gpio path %s\n", path);
		return 0;
	}
	fprintf(f, "%s", (out) ? "out" : "in");
	fclose(f);

	return 1;
}

static void gpio_set_value(int gpio, int value)
{
	int fd = gpio_fds[gpio];

	if (gpio_state[gpio] != value) {
		write(fd, (value) ? "1" : "0", 1);
		gpio_state[gpio] = value;
	}
}

static int gpio_get_value(int gpio)
{
	int fd = gpio_fds[gpio];
	char val;

	pread(fd, &val, 1, 0);
	return val == '1';
}

static int gpio_open(int gpionum)
{
	char path[64];
	int fd;

	snprintf(path, sizeof(path)-1, "%s/gpio%d/value", GPIO_PATH, gpionum);

	fd = open(path, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Could not open gpio path %s\n", path);
		return -1;
	}

	return fd;
}

static void gpio_close(int fd)
{
	close(fd);
}

static void initialize_jtag_hardware()
{
	int i;

	for (i = 0; i < 4; i++) {
		gpio_export(gpio_pins[i], 1);
		if (i == GPIO_TDO) {
			gpio_direction(gpio_pins[i], 0);
		} else {
			gpio_direction(gpio_pins[i], 1);
		}
		gpio_fds[i] = gpio_open(gpio_pins[i]);
		if (gpio_fds[i] == -1) return;
	}
}

static void close_jtag_hardware()
{
	int i;
	for (i = 0; i < 4; i++) {
		gpio_close(gpio_fds[i]);
		gpio_direction(gpio_pins[i], 0);
		gpio_export(gpio_pins[i], 0);
	}
}

int altera_jtag_io(int tms, int tdi, int read_tdo)
{
	int tdo = 0;

	if (!jtag_hardware_initialized)
	{
		initialize_jtag_hardware();
		jtag_hardware_initialized = 1;
	}

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

int main(int argc, char **argv)
{
	int help = 0;
	int error = 0;
	char *filename = NULL;
	int32_t offset = 0L;
	int32_t error_address = 0L;
	int crc_result = ALTERA_SUCCESS;
	int exec_result = ALTERA_SUCCESS;
	char key[33] = {0};
	char value[257] = {0};
	int exit_status = 0;
	int arg = 0;
	int exit_code = 0;
	int format_version = 0;
	time_t start_time = 0;
	time_t end_time = 0;
	int time_delta = 0;
	char *action = NULL;
	struct altera_varinit *init_list[10];
	int init_count = 0;
	FILE *fp = NULL;
	struct stat sbuf;
	const char *exit_string = NULL;
	int execute_program = 1;
	int action_count = 0;
	int procedure_count = 0;
	int index = 0;
	char *action_name = NULL;
	char *description = NULL;
	struct altera_procinfo *procedure_list = NULL;
	struct altera_procinfo *procptr = NULL;
	unsigned char *file_buffer = NULL;
	size_t file_length = 0L;

	verbose = 0;

	init_list[0] = NULL;

	/* print out the version string and copyright message */
	fprintf(stderr, "Jam STAPL ByteCode Player Version %s\n", VERSION);

	for (arg = 1; arg < argc; arg++) {
		if (argv[arg][0] == '-') {
			switch(argv[arg][1]) {
			case 'a':				/* set action name */
				if (action == NULL) {
					action = &argv[arg][2];
				} else {
					error = 1;
				}
				break;

			case 'd':				/* initialization list */
			{
				char *name = &argv[arg][2];
				char *value_str = strchr(name, '=');
				uint32_t value;

				if (name && value_str) {
					*(value_str++) = '\n';
					value = strtoul(value_str, NULL, 0);

					init_list[init_count] = malloc(sizeof(struct altera_varinit));
					init_list[init_count]->name = name;
					init_list[init_count]->value = value;
				}

				init_list[++init_count] = NULL;
			} break;

			case 'h':				/* help */
				help = 1;
				break;

			case 'v':				/* verbose */
				verbose = 1;
				break;

			case 'i':				/* show info only, do not execute */
				verbose = 1;
				execute_program = 0;
				break;

			case 'g':				/* gpio pin numbers */
			{
				char *argstr = &argv[arg][2];
				int i;
				char *c;
				for (i = 0; i < 4; i++) {
					gpio_pins[i] = strtoul(argstr, &c, 10);
					if ((i < 3 && *c != ':') || (i == 3 && *c != '\0')) {
						error = 1;
						break;
					}
					argstr = c+1;
				}
			} break;
			default:
				error = 1;
				break;
			}
		} else {
			/* it's a filename */
			if (filename == NULL) {
				filename = argv[arg];
			} else {
				/* error -- we already found a filename */
				error = 1;
			}
		}

		if (error) {
			fprintf(stderr, "Illegal argument: \"%s\"\n", argv[arg]);
			help = 1;
			error = 0;
		}
	}

	if (help || (filename == NULL)) {
		fprintf(stderr, "Usage:  jbi [options] <filename>\n");
		fprintf(stderr, "\nAvailable options:\n");
		fprintf(stderr, "    -h          : show help message\n");
		fprintf(stderr, "    -v          : show verbose messages\n");
		fprintf(stderr, "    -i          : show file info only - does not execute any action\n");
		fprintf(stderr, "    -a<action>  : specify an action name (Jam STAPL)\n");
		fprintf(stderr, "    -d<var=val> : initialize variable to specified value (Jam 1.1)\n");
		fprintf(stderr, "    -d<proc=1>  : enable optional procedure (Jam STAPL)\n");
		fprintf(stderr, "    -d<proc=0>  : disable recommended procedure (Jam STAPL)\n");
		fprintf(stderr, "    -r          : don't reset JTAG TAP after use\n");
		fprintf(stderr, "    -g<gpios>   : set gpio pin numbers, see below\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "GPIO pin numbers are given in the following format:\n");
		fprintf(stderr, "  <TCK>:<TDO>:<TDI>:<TMS> eg. 218:220:219:221\n");
		exit_status = 1;
	} else if (gpio_pins[0] == 0 && gpio_pins[1] == 0) {
		fprintf(stderr, "No GPIO pins specified\n");
		exit_status = 1;
	} else if (access(filename, 0) != 0) {
		fprintf(stderr, "Error: can't access file \"%s\"\n", filename);
		exit_status = 1;
	} else {
		/* get length of file */
		if (stat(filename, &sbuf) == 0) file_length = sbuf.st_size;

		if ((fp = fopen(filename, "rb")) == NULL)
		{
			fprintf(stderr, "Error: can't open file \"%s\"\n", filename);
			exit_status = 1;
		} else {
			/*
			*	Read entire file into a buffer
			*/
			file_buffer = malloc(file_length);

			if (file_buffer == NULL)
			{
				fprintf(stderr, "Error: can't allocate memory (%d Kbytes)\n",
					(int) (file_length / 1024L));
				exit_status = 1;
			} else {
				if (fread(file_buffer, 1, (size_t) file_length, fp) !=
					(size_t) file_length)
				{
					fprintf(stderr, "Error reading file \"%s\"\n", filename);
					exit_status = 1;
				}
			}

			fclose(fp);
		}

		if (exit_status == 0) {
			/*
			*	Check CRC
			*/
			crc_result = altera_check_crc(file_buffer, file_length);

			if (verbose || (crc_result == ALTERA_CRC_ERROR))
			{
				switch (crc_result)
				{
				case ALTERA_SUCCESS:
					printf("CRC matched\n");
					break;

				case ALTERA_CRC_ERROR:
					printf("CRC mismatch\n");
					break;

				case ALTERA_IO_ERROR:
					printf("Error: File format is not recognized.\n");
					exit(1);
					break;

				default:
					printf("CRC function returned error code %d\n", crc_result);
					break;
				}
			}

			if (verbose) {
				/*
				*	Display file format version
				*/
				altera_get_file_info(file_buffer, file_length,
					&format_version, &action_count, &procedure_count);

				printf("File format is %s ByteCode format\n",
					(format_version == 2) ? "Jam STAPL" : "pre-standardized Jam 1.1");

				/*
				*	Dump out NOTE fields
				*/
				while (altera_get_note(file_buffer, file_length,
					&offset, key, value, 256) == 0)
				{
					printf("NOTE \"%s\" = \"%s\"\n", key, value);
				}

				/*
				*	Dump the action table
				*/
				if ((format_version == 2) && (action_count > 0))
				{
					printf("\nActions available in this file:\n");

					for (index = 0; index < action_count; ++index)
					{
						altera_get_act_info(file_buffer, file_length,
							index, &action_name, &description, &procedure_list);

						if (description == NULL)
						{
							printf("%s\n", action_name);
						}
						else
						{
							printf("%s \"%s\"\n", action_name, description);
						}

						procptr = procedure_list;
						while (procptr != NULL)
						{
							if (procptr->attrs != 0)
							{
								printf("    %s (%s)\n", procptr->name,
									(procptr->attrs == 1) ?
									"optional" : "recommended");
							}

							procedure_list = procptr->next;
							free(procptr);
							procptr = procedure_list;
						}
					}

					/* add a blank line before execution messages */
					if (execute_program) printf("\n");
				}
			}

			if (execute_program) {
				/*
				 *	Execute the Jam STAPL ByteCode program
				 */
				time(&start_time);
				exec_result = altera_execute(file_buffer, file_length, action,
					init_list, &error_address, &exit_code, &format_version);
				time(&end_time);

				if (exec_result == ALTERA_SUCCESS) {
					exit_string = "Unknown exit code";
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
						exit_status = 2;
					}

					printf("Exit code = %d... %s\n", exit_code, exit_string);
				} else if ((format_version == 2) &&
					(exec_result == ALTERA_ACTION_NOT_FOUND)) {
					if ((action == NULL) || (*action == '\0'))
					{
						printf("Error: no action specified for Jam STAPL file.\nProgram terminated.\n");
						exit_status = 5;
					}
					else
					{
						printf("Error: action \"%s\" is not supported for this Jam STAPL file.\nProgram terminated.\n", action);
						exit_status = 6;
					}
				} else if (exec_result < ALTERA_MAX_ERROR) {
					printf("Error at address %d: %s.\nProgram terminated.\n",
						error_address, error_text[exec_result]);
					exit_status = 99;
				} else {
					printf("Unknown error code %d\n", exec_result);
					exit_status = 100;
				}

				/*
				 *	Print out elapsed time
				 */
				if (verbose) {
					time_delta = (int) (end_time - start_time);
					printf("Elapsed time = %02u:%02u:%02u\n",
						time_delta / 3600,			/* hours */
						(time_delta % 3600) / 60,	/* minutes */
						time_delta % 60);			/* seconds */
				}
			}
		}
	}

	if (jtag_hardware_initialized) {
		close_jtag_hardware();
	}
	free(file_buffer);

	return exit_status;
}

