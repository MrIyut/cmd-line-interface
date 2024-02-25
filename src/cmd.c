// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
char *current_dir;
int cd_init;
int saved_stdout = -1, saved_stderr = -1, saved_stdin = -1;
int saved_out = -1, saved_err = -1, saved_in = -1;

static void perform_redirections(simple_command_t *s) {
	int append = s->io_flags;
	char *in = s->in ? get_word(s->in) : NULL;
	char *out = s->out ? get_word(s->out) : NULL;
	char *err = s->err ? get_word(s->err) : NULL;

	if (out && err && strcmp(out, err) == 0)
		append = 3; // case for &>

	if (in) {
		saved_stdin = dup(STDIN_FILENO);
		saved_in = open(in, O_RDONLY);
		dup2(saved_in, STDIN_FILENO);
	}
	if (out) {
		saved_stdout = dup(STDOUT_FILENO);
		int flags = O_RDWR | O_CREAT | (append ? O_APPEND : O_TRUNC);

		if (append == 3)
			flags |= O_TRUNC;
		saved_out = open(out, flags, S_IRUSR | S_IWUSR);
		dup2(saved_out, STDOUT_FILENO);
	}
	if (s->err) {
		saved_stderr = dup(STDERR_FILENO);
		int flags = O_RDWR | O_CREAT | (append ? O_APPEND : O_TRUNC);

		if (append == 3)
			flags |= O_TRUNC;
		saved_err = open(err, flags, S_IRUSR | S_IWUSR);
		dup2(saved_err, STDERR_FILENO);
	}

	if (in)
		free(in);
	if (out)
		free(out);
	if (err)
		free(err);
}

static void reset_redirections(void) {
	if (saved_stdin != -1) {
		dup2(saved_stdin, STDIN_FILENO);
		close(saved_stdin);
		close(saved_in);
		saved_stdin = -1;
	}
	if (saved_stdout != -1) {
		dup2(saved_stdout, STDOUT_FILENO);
		close(saved_stdout);
		close(saved_out);
		saved_stdout = -1;
	}
	if (saved_stderr != -1) {
		dup2(saved_stderr, STDERR_FILENO);
		close(saved_stderr);
		close(saved_err);
		saved_stderr = -1;
	}
}

static void init_cd(void) {
	if (cd_init)
		return;

	cd_init = 1;
	char buffer[4096];

	getcwd(buffer, sizeof(buffer) - 1);
	current_dir = calloc(strlen(buffer) + 1, sizeof(char));
	memcpy(current_dir, buffer, strlen(buffer));
}

static bool shell_cd(simple_command_t *s) {
	if (!s->params || s->params->next_word)
		return TOO_MANY_ARGUMENTS;

	char *path = get_word(s->params);
	if (path[0] == '/') {
		int rc = chdir(path);
		if (rc == -1) {
			free(path);
			return errno;
		}
		free(current_dir);
		current_dir = calloc(strlen(path) + 1, sizeof(char));
		memcpy(current_dir, path, strlen(path));
		free(path);
		return 0;
	}

	char buffer[4096];
	memcpy(buffer, current_dir, strlen(current_dir) + 1);
	if (buffer[strlen(buffer) - 1] == '/')
		buffer[strlen(buffer) - 1] = '\0';

	char *original_path = path;
	char *token = strtok_r(path, "/", &path);

	while (token != NULL) {
		if (strcmp(token, ".") == 0) {
		} else if (strcmp(token, "..") == 0) {
			for (int i = strlen(buffer) - 1; i >= 0; i--) {
				int doBreak = buffer[i] == '/';

				buffer[i] = '\0';
				if (doBreak)
					break;
			}
		} else {
			int offset = strlen(buffer);

			buffer[offset] = '/';
			memcpy(buffer + offset + 1, token, strlen(token) + 1);
		}

		token = strtok_r(path, "/", &path);
	}
	free(original_path);

	int rc = chdir(buffer);
	if (rc == -1)
		return errno;

	free(current_dir);
	current_dir = calloc(strlen(buffer) + 1, sizeof(char));
	memcpy(current_dir, buffer, strlen(buffer));
	return 0;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void) {
	free(current_dir);
	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father) {
	if (!s || !s->verb || !s->verb->string)
		return NO_COMMAND_EXIT;

	char *command = get_word(s->verb);
	if (strcmp(command, "cd") == 0) {
		free(command);
		perform_redirections(s);
		int result = shell_cd(s);

		reset_redirections();
		return result;
	}
	if (strcmp(command, "exit") == 0 || strcmp(command, "quit") == 0) {
		free(command);
		return shell_exit();
	}

	if (s->verb->next_part && strcmp(s->verb->next_part->string, "=") == 0) {
		size_t cmd_len = strlen(command);
		size_t var_len = strlen(s->verb->string);
		size_t val_len = cmd_len - var_len - 1;
		char var[var_len + 1], val[val_len + 1];

		memcpy(var, s->verb->string, var_len + 1);
		memcpy(val, command + var_len + 1, val_len + 1);

		int rc = setenv(var, val, 1);
		rc = rc == 0 ? rc : -1 * errno;
		free(command);
		return rc;
	}

	pid_t pid = fork();
	if (pid == -1) {
		free(command);
		return SHELL_EXIT;
	}

	if (pid > 0) {
		int status;
		waitpid(pid, &status, 0);
		free(command);
		return status;
	}

	perform_redirections(s);
	char exec_path[4096];

	if (command[0] == '.' && command[1] == '/')
		sprintf(exec_path, "%s/%s", current_dir, command + 2);
	else if (command[0] == '/')
		sprintf(exec_path, "%s", command);
	else
		sprintf(exec_path, "%s%s", DEFAULT_EXEC_PATH, command);

	int size;
	char **args = get_argv(s, &size);

	execv(exec_path, args);
	printf("Execution failed for '%s'\n", command);
	exit(NO_COMMAND_EXIT);
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father) {
	pid_t pid_cmd1, pid_cmd2;
	int status = true;

	pid_cmd1 = fork();
	if (pid_cmd1 == 0) {
		status = parse_command(cmd1, level + 1, father) == 0 ? false : true;
		exit(status);
	}

	pid_cmd2 = fork();
	if (pid_cmd2 == 0) {
		status = parse_command(cmd2, level + 1, father) == 0 ? false : true;
		exit(status);
	}

	int status_cmd1, status_cmd2;
	waitpid(pid_cmd1, &status_cmd1, 0);
	waitpid(pid_cmd2, &status_cmd2, 0);
	status = (status_cmd1 == 0 && status_cmd2 == 0) ? false : true;
	return status;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father) {
	pid_t pid_cmd1, pid_cmd2;
	int status = true;
	int pipefd[2];

	pipe(pipefd);
	pid_cmd1 = fork();
	if (pid_cmd1 == 0) {
		dup2(pipefd[1], STDOUT_FILENO);
		status = parse_command(cmd1, level + 1, father) == 0 ? false : true;
		exit(status);
	}

	pid_cmd2 = fork();
	if (pid_cmd2 == 0) {
		close(pipefd[1]);
		dup2(pipefd[0], STDIN_FILENO);
		status = parse_command(cmd2, level + 1, father) == 0 ? false : true;
		exit(status);
	}
	close(pipefd[0]);
	close(pipefd[1]);

	int status_cmd1, status_cmd2;
	waitpid(pid_cmd1, &status_cmd1, 0);
	waitpid(pid_cmd2, &status_cmd2, 0);
	status = status_cmd2 == 0 ? false : true; // pipe return code is determined by the filter command
	return status;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father) {
	init_cd();
	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level, father);

	int status_code = 0;
	switch (c->op) {
	case OP_SEQUENTIAL:
		status_code = parse_command(c->cmd1, level + 1, c);
		if (status_code >= 0)
			status_code = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		status_code = run_in_parallel(c->cmd1, c->cmd2, level, c);
		break;

	case OP_CONDITIONAL_NZERO:
		status_code = parse_command(c->cmd1, level + 1, c);
		if (status_code != 0)
			status_code = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		status_code = parse_command(c->cmd1, level + 1, c);
		if (status_code == 0)
			status_code = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		status_code = run_on_pipe(c->cmd1, c->cmd2, level, c);
		break;

	default:
		return SHELL_EXIT;
	}

	return status_code;
}
