# Nagios® TYPO3 Monitoring

## Configuration

In broad terms there are two areas where the plugin needs to be configured:

1. command line arguments
2. configuration file

The command line arguments allow you to pass server-related arguments to the plugin, e.g. the hostname, the exact URI of the TYPO3 server, the limits for the disk usage checks, the path/filename of the configuration file (see below) and some more.

You find a complete list of possibly command line options when executing the script with the following argument:

```
/usr/local/nagios/libexec/check_typo3.sh --help
```

The second level of configuration is the file `check_typo3.cfg`. This file controls how the plugin should react when it reads and parses the data from the TYPO3 instance (e.g. report a critical error to the Nagios® core or just a warning, etc.).

For example: it is possible to configure that Nagios® notifies system administrators about a *CRITICAL* state, if a specific TYPO3 extension in a specific version is installed on the TYPO3 system. This is very useful if the TYPO3 Security Team publishes a [security bulletin](https://typo3.org/teams/security/security-bulletins) about a new vulnerability found in one of the extensions.

Another scenario would be to monitor TYPO3 core versions: a Nagios® system with the TYPO3 plugin can monitor a range of TYPO3 instances/servers. The *OK*-state shows the current TYPO3 core version. By a simple configuration change on the Nagios® side, Nagios® can warn system administrators about a specific (e.g. outdated) TYPO3 version.

In most cases you only need one configuration file for all TYPO3 servers you monitor. However it is possible to specify the path/filename of the configuration file by a command line argument. So, you could configure that TYPO3 server "A" uses a different configuration file than server "B" (with different checks, different behaviour, etc.).

```
# TYPO3 Server A
define service {
  [...]
  check_command check_typo3!--hostname typo3-server-a.org --config ../etc/check_typo3_a.cfg
  [...]
}

# TYPO3 Server B
define service {
  [...]
  check_command check_typo3!--hostname typo3-server-b.org --config ../etc/check_typo3_b.cfg
  [...]
}
```

Without the `--config` argument, the plugin searches for the configuration file `check_typo3.cfg` in the same directory as the script then in the Nagios®'s `etc/` directory, typically:

1. `/usr/local/nagios/libexec/check_typo3.cfg`
2. `/usr/local/nagios/etc/check_typo3.cfg`

Open the configuration file with your favourite text editor (e.g. "vi") and investigate the diverse options. The file is pretty self-explaining (check the comments).

```
vi /usr/local/nagios/etc/check_typo3.cfg
```

Customize the configuration file depending on your individual needs but keep in mind that you have to maintain it on an ongoing basis. This means for example if the TYPO3 Security Team publishes a new security bulletin about a vulnerability of a TYPO3 extension, you should add the extension key and affected version(s) to the configuration file (as soon as possible).

If you do not want to maintain your own configuration file, you can download an automatically generated file from <https://schams.net/nagios> (under "Downloads").


## Auto Update

An automatic update feature is planned but not completed/tested yet.


## Command Line Options

The following arguments are currently supported as command line options.

**Informative arguments:**
```
  -h, --help
       Print detailed help screen

  -V, --version, --revision
       Print version information
```

**Mandatory arguments:**
```
  -H <fqhostname>, --hostname <fqhostname>
       Full qualified host name of TYPO3 server (e.g. "typo3.org")
       A port can be appended if required (e.g.: typo3.org:8080)
       This argument is also used to determine the request to the TYPO3 server but can be
       overwritten by using the -r (or --resource) argument.

       The output of the TYPO3 Nagios extension is expected at:
       "http://<fqhostname>/index.php?eID=nagios"
```

**Optional arguments:**
```
  -c <configfile>, --config <configfile>
       Path and filename to configuration file. Default: "check_typo3.cfg",
       located in Nagios' etc-directory.

  -t <timeout>, --timeout <timeout>
       Timeout in seconds. Nagios check fails (return: CRITICAL) if timeout exceeded.
       This timeout value applies to DNS lookup timeout, connect timeout and read timeout.
       Default: 5

  -u <username>, --http-user <username>
       HTTP user name (string) for HTTP access authentication (HTTP status code: 401)

  -p <password>, --http-password <password>
       HTTP password (string) for HTTP access authentication (HTTP status code: 401)

  -r <uri>, --resource <uri>
       URI (Uniform Resource Identifier) of TYPO3 server's Nagios extension output.
       Example: "-r http://typo3.org/index.php?eID=nagios"
       Note that this argument is optional. The Nagios plugin uses --hostname (or -H) to
       determine the URI of the TYPO3 server. If <uri> starts with "/", <fqhostname> is
       prepended. If you use this argument, it overwrites arguments -pid and --pageid

  -I <ip-address>, --ipaddress <ip-address>
       IPv4 address of the TYPO3 server (e.g. "123.45.67.89")
       If this argument is used, the hostname (argument -H or --hostname) is sent as
       "Host:" in the HTTP header of the request.

  -duw <limit>, --diskusagewarning <limit>
       Warning level for disk usage (should be less than -duc).
       Value MUST have one of these units appended: k, M, G, T or P.
       A valid value for this argument would be "512M" for example.

  -duc <limit>, --diskusagecritical <limit>
       Critical level for disk usage.
       Value MUST have one of these units appended: k, M, G, T or P.
       A valid value for this argument would be "512M" for example.

  --deprecationlog-action <action>
       One of the following actions, if an enabled deprecation log has been detected:
       "ignore"    do nothing, ignore enabled deprecation logs
       "warning"   generate a warning condition in Nagios
       "critical"  generate a critical condition in Nagios
       Default: warning

  --server-messages-action <action>
       What should the check script do, if TYPO3 server sends an additional message in
       the output:
       "ignore"    do nothing and do not show messages (not recommended)
       "show"      show messages if they occur (they can be useful)

  --unknown-extension-version-action <action>
       What should the check script do, if the TYPO3 server reports an extension with
	   an invalid version:
       "ignore"    ignore the extension do not show the extension at all (not recommended)
       "show"      do not raise a warning/error but show the version string as it is
       "unknown"   generate a unknown condition in Nagios
       Default: unknown
```

**Deprecated (but still supported) arguments:**
```
  -pid <pageid>, --pageid <pageid>
       Page ID (numeric value) of TYPO3 instance with TYPO3 extension "nagios"
       See argument "--resource" and note below.

       Note: HTTP request string to TYPO3 server becomes "index.php?id=<pageid>" if argument
       -pid or --pageid is given. Alternatively, parameter --resource can be used to define
       the path to a page (may be useful if TYPO3 instance uses SEO extensions). However,
       be aware of the fact that the -pid and --pageid method is DEPRECATED and you should
       use the eID method (which is the default behaviour).
```
