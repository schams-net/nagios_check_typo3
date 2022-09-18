# Nagios® TYPO3 Monitoring

## Installation

Install Nagios® as documented. We assume your Nagios® server if fully operational, configured and tested. We also assume all Nagios® plugins are located in folder `/usr/local/nagios/libexec/`.

Copy file `check_typo3.sh` to `/usr/local/nagios/libexec/`
Copy file `check_typo3.cfg` to `/usr/local/nagios/etc/`

Make sure, file permissions are correct. For example (depending on your individual system):

```bash
chown nagios /usr/local/nagios/libexec/check_typo3.sh
chmod 755 /usr/local/nagios/libexec/check_typo3.sh
chmod 644 /usr/local/nagios/etc/check_typo3.cfg
```

Install and set up the [TYPO3 extension](https://extensions.typo3.org/extension/nagios) on the TYPO3 server(s). You find a detailed information about the installation process in the [documentation](https://github.com/schams-net/nagios/tree/release/Documentation).

In the next step, integrate the *TYPO3 check* in your Nagios® configuration. For example:

```
define command {
  command_name            check_typo3
  command_line            $USER1$/check_typo3.sh $ARG1$
}

define service {
  use                     generic-service
  host_name               my-typo3-host
  service_description     TYPO3
  check_command           check_typo3!--hostname example.com
  normal_check_interval   60
  retry_check_interval    10
  notifications_enabled   1
}
```

Note: this is an example only! Change `example.com` accordingly.

The plugin supports a number of arguments to tweak the configuration and achieve a great level of sophistication. You find a complete list of available options in the configuration manual.

Reload (or restart) the Nagios® server and check if everything works as expected or if the server reports an error. A successful reload looks like:

```
Running configuration check...done.
Reloading nagios configuration...done
```

If the Nagios® server reports a configuration error (see example below), you made a mistake in one of the configuration files. In this case, double check your Nagios® configuration.

```
Running configuration check... CONFIG ERROR!
Reload aborted. Check your Nagios configuration.
```

Assuming the reload/restart of the Nagios® server was successful, continue with your individual configuration as described in the configuration manual.
