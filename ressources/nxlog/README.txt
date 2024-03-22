Please edit the configuration file after installation. This file is
located in the `conf` directory where NXLog was installed (default
`C:\Program Files (x86)\nxlog\conf\nxlog.conf` on 64-bit Windows). If
you chose a custom installation directory, you will need to update the
ROOT directory specified in the configuration file before the NXLog
service will start.

The NXLog service can be started from the Services console (run
`services.msc`) or will be started automatically at the next
boot. Alternatively, the service can be started by executing
`nxlog.exe`, located in the installation directory. The `-f` command
line argument can be used to run NXLog in the foreground.

By default, NXLog will write its own messages to the log file named
`nxlog.log` in the `data` directory (default `C:\Program Files
(x86)\nxlog\data\nxlog.log` on 64-bit Windows). If you have trouble
starting or running NXLog, check that file for errors.

See the NXLog Reference Manual for details about configuration and
usage. The Reference Manual is installed in the `doc` directory
(default `C:\Program Files (x86)\nxlog\doc` on 64-bit Windows) and
should also be available online at <https://nxlog.co/resources>.
