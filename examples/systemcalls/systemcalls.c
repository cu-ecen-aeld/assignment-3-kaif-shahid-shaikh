#include "systemcalls.h"
#include <stdlib.h>     // system
#include <stdbool.h>
#include <stdarg.h>     // va_list, va_start, va_end
#include <sys/types.h>  // pid_t
#include <sys/wait.h>   // waitpid, WIFEXITED, WEXITSTATUS
#include <unistd.h>     // fork, execv, _exit, dup2, close, STDOUT_FILENO
#include <fcntl.h>      // open, O_*
#include <stdio.h>      // fflush
/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
 if (cmd == NULL) return false;

    int rc = system(cmd);
    if (rc == -1) return false;

    return WIFEXITED(rc) && (WEXITSTATUS(rc) == 0);
/*
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;

    fflush(stdout); // avoid duplicate prints after fork
    pid_t pid = fork();
    if (pid < 0) {
        va_end(args);
        return false;   // fork failed
    }

    if (pid == 0) {
        // child process
        execv(command[0], command);
        _exit(1);       // only reached if execv fails
    }

    int status = 0;
    if (waitpid(pid, &status, 0) == -1) {
        va_end(args);
        return false;   // waitpid failed
    }

    va_end(args);
    return WIFEXITED(status) && (WEXITSTATUS(status) == 0);


/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/

}

bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        va_end(args);
        return false;   // fork failed
    }

    if (pid == 0) {
        // child process
        int fd = open(outputfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) _exit(1);
        if (dup2(fd, STDOUT_FILENO) < 0) {
            close(fd);
            _exit(1);
        }
        close(fd);

        execv(command[0], command);
        _exit(1);   // only reached if execv fails
    }

    int status = 0;
    if (waitpid(pid, &status, 0) == -1) {
        va_end(args);
        return false;
    }

    va_end(args);
    return WIFEXITED(status) && (WEXITSTATUS(status) == 0);


/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/
}
