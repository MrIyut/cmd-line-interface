/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _CMD_H
#define _CMD_H

#include "../util/parser/parser.h"

#define SHELL_EXIT -100
#define NO_COMMAND_EXIT -127
#define TOO_MANY_ARGUMENTS -1

#define DEFAULT_EXEC_PATH "/usr/bin/"
/**
 * Parse and execute a command.
 */
int parse_command(command_t *cmd, int level, command_t *father);

#endif /* _CMD_H */
