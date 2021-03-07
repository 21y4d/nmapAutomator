# Contributing Guidelines

## Coding Standards

`nmapAutomator` is 100% POSIX compatible, and should run with `/bin/sh`. To keep it compatible, please try to follow these Coding Standards:
- Keep the current indentation and code structure. *You can use VSCode to automatically format it.*
- For any variables/functions added, please use Camel Casing 'e.g. `newVariable`'.
- For any output files, please use underscores `_` instead of spaces, and include the `${HOST}` in the name.
- Enclose all variables in `${}` 'e.g. `${myVar}`'
- Always quote the variables 'e.g. `echo "${my_var}"`', *unless you're doing shell-splitting.*
- Always add a comment describing the general purpose of the code 
- Use POSIX commands where possible 'i.e. `awk`/`sed`', as some commands may not work with `sh` or older shells. *You may open an issue if you don't know how to write the command you need.*

You can check the POSIX tools (and the parameters and syntax they accept) in the [IEEE Std 1003.1-2017 Utilities specification](https://pubs.opengroup.org/onlinepubs/9699919799/idx/utilities.html), and the [IEEE Std 1003.1-2017 Built-ins specification](https://pubs.opengroup.org/onlinepubs/9699919799/idx/sbi.html).

Furthermore, you can always re-use existing code, by looking for adding new recon options, by basing your pull request on existing options in the `reconRecommend()` function.
