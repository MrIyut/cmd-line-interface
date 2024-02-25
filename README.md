# Minishell

## Description 

Bash-like shell with minimal functionalities like traversing the file system, running applications, redirecting their output or piping the output from one application into the input of another.
The details of the functionalities that are implemented will be further explained.

### Shell Functionalities

#### Changing the Current Directory

The shell will support a built-in command for navigating the file system, called `cd`.
The built-in `pwd` command will show the current directory path.

> **_NOTE:_** Using the `cd` command without any arguments or with more than one argument doesn't affect the current directory path.

#### Closing the Shell

Inputting either `quit` or `exit` should close the minishell.

#### Running an Application

Supports running executable with both absolute and relative paths and prints there output to `stdout`, unless specified otherwise.

#### Environment Variables

Supports using environment variables.
The environment variables will be initially inherited from the `bash` process that started your minishell application.
If an undefined variable is used, its value is the empty string: `""`.

> **_EXAMPLE USAGE_** 

```sh
> NAME="John Doe"                    # Will assign the value "John Doe" to the NAME variable
> AGE=27                             # Will assign the value 27 to the AGE variable
> ./identify $NAME $LOCATION $AGE    # Will translate to ./identify "John Doe" "" 27 because $LOCATION is not defined
```

A variable can be assigned to another variable.

```sh
> OLD_NAME=$NAME    # Will assign the value of the NAME variable to OLD_NAME
```

#### Operators

##### Sequential Operator

By using the `;` operator, you can chain multiple commands that will run sequentially, one after another.
In the command `expr1; expr2` it is guaranteed that `expr1` will finish before `expr2` is be evaluated.

```sh
> echo "Hello"; echo "world!"; echo "Bye!"
Hello
world!
Bye!
```

##### Parallel Operator

By using the `&` operator you can chain multiple commands that will run in parallel.
When running the command `expr1 & expr2`, both expressions are evaluated at the same time (by different processes).
The order in which the two commands finish is not guaranteed.

```sh
> echo "Hello" & echo "world!" & echo "Bye!"  # The words may be printed in any order
world!
Bye!
Hello
```

##### Pipe Operator

With the `|` operator you can chain multiple commands so that the standard output of the first command is redirected to the standard input of the second command.

```sh
> echo "Bye"                      # command outputs "Bye"
Bye
> ./reverse_input
Hello                             # command reads input "Hello"
olleH                             # outputs the reversed string "olleH"
> echo "world" | ./reverse_input  # the output generated by the echo command will be used as input for the reverse_input executable
dlrow
```

##### Chain Operators for Conditional Execution

The `&&` operator allows chaining commands that are executed sequentially, from left to right.
The chain of execution stops at the first command **that exits with an error (return code not 0)**.

```sh
# throw_error always exits with a return code different than 0 and outputs to stderr "ERROR: I always fail"
> echo "H" && echo "e" && echo "l" && ./throw_error && echo "l" && echo "o"
H
e
l
ERROR: I always fail
```

The `||` operator allows chaining commands that are executed sequentially, from left to right.
The chain of execution stops at the first command **that exits successfully (return code is 0)**.

```sh
# throw_error always exits with a return code different than 0 and outputs to stderr "ERROR: I always fail"
> ./throw_error || ./throw_error || echo "Hello" || echo "world!" || echo "Bye!"
ERROR: I always fail
ERROR: I always fail
Hello
```

##### Operator Priority

The priority of the available operators is the following.
The lower the number, the **higher** the priority:

1. Pipe operator (`|`)
1. Conditional execution operators (`&&` or `||`)
1. Parallel operator (`&`)
1. Sequential operator (`;`)

#### I/O Redirection

The shell supports the following redirection options:

- `< filename` - redirects `filename` to standard input
- `> filename` - redirects standard output to `filename`
- `2> filename` - redirects standard error to `filename`
- `&> filename` - redirects standard output and standard error to `filename`
- `>> filename` - redirects standard output to `filename` in append mode
- `2>> filename` - redirects standard error to `filename` in append mode