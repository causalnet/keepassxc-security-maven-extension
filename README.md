# KeepassXC Security Maven Extension

An extension for Maven that allows it to use KeepassXC to store and retrieve
passwords in `settings.xml` instead of using Maven's built-in password encryption 
mechanism.  It will make Maven act as a client to KeepassXC, similar to how the KeepassXC
browser extension works.

## Requirements

- Maven 3.x
- Java 17 or later (required for Java Unix domain sockets support)
- KeepassXC running on your system

## Installation

The extension needs to be downloaded and registered with Maven as an extension.

### Downloading

This can be done easily through Maven itself, downloading the extension Maven Central to your
local repository with:

```
mvn dependency:get -Dartifact=au.net.causal.maven.plugins:keepassxc-security-maven-extension:1.0
```

### Registering the extension

The easiest and least invasive way of registering the extension is modifying the `MAVEN_OPTS`
environment variable to contain:

```
-Dmaven.ext.class.path=<your m2 directory>/repository/au/net/causal/maven/plugins/keepassxc-security-maven-extension/1.0/keepassxc-security-maven-extension-1.0.jar
```

If you already have `maven.ext.class.path` set up in `MAVEN_OPTS`, add this extension to the end with
your platform's path separator (';' on Windows, ':' on Mac/Linux).

Alternatively, you can copy the extension's JAR file into your Maven installation's `lib/ext` directory,
but this installs it globally for all users.

### settings-security.xml

A `settings-security.xml` file must exist in your `.m2` directory (under your user home directory) for this extension to work.
Even if you KeepassXC for all your passwords and don't use 
[Maven's built-in encryption/master key support](https://maven.apache.org/guides/mini/guide-encryption.html)
this XML file still must exist, so if you don't have one, create an empty one containing:

```
<settingsSecurity />
```

## Usage

Once the extension is installed, add servers passwords in your `settings.xml` in this form:

```
<server>
    <id>myserver</id>
    <username>myuser</username>
    <password>{[type=keepassxc]https://www.myserver.com}</password>
</server>
```

Maven will use the extension to read the password for `https://www.myserver.com` from
KeepassXC.  You will need an entry in your KeepassXC database for this URL and the database
will need to be running and unlocked when using Maven.

It is also possible to select KeepassXC entries not just by URL, but by username or custom
attributes if needed.  It is also possible to read some custom attributes, not just passwords.

If KeepassXC is not running or the database is not unlocked when Maven needs a password,
a message will be displayed
`Maven needs to read passwords from Keepass, please unlock your database (timeout in PT20S)...`
and the build will be blocked until you unlock your Keepass database, or it times out.

For the first time connecting Maven to KeepassXC, you will be asked to associate the
Maven extension to KeepassXC,
[similarly to how the browser extension is paired](https://keepassxc.org/docs/KeePassXC_GettingStarted.html#_configure_keepassxc_browser).  
When this happens, give the connection a name and the pairing will be remembered by the
extension so you won't need to do this again.
For each entry that Maven attempts to access, KeepassXC will ask you whether you allow
access (exactly how the browser extension works).  If you don't want this prompt to appear
every time you run Maven, it is recommended to select 'Allow' and 'remember'.

KeepassXC needs to be
[configured to allow browser extensions](https://keepassxc.org/docs/KeePassXC_GettingStarted.html#_configure_keepassxc_browser).  
If this extension cannot connect to KeepassXC, ensure the 'Enable browser integration' setting
is enabled in KeepassXC.  No specific browser type needs to be selected, but the 'Enable browser integration'
setting must be switched on.

## Advanced Usage

### Custom attributes in Keepass entries

[Custom attribute](https://keepassxc.org/docs/KeePassXC_UserGuide.html#_additional_attributes) 
values may be read and/or filtered on by this extension.  The custom attribute names 
[must be prefixed](https://keepassxc.org/docs/#faq-browser-string-fields) 
with 'KPH: ' (including the space) so that any KeepassXC browser/extension can access it.
This is not a restriction with this extension, but with KeepassXC itself.

### Filtered selection

In most cases, simply having an entry that selects by URL will be adequate.  However, 
there may be cases where there are multiple entries with the same URL but having different
other properties, such as username.  It is possible to make an settings.xml Keepass entry
further narrow selection from Keepass using a filter.  For example:

```
<password>{[type=keepassxc,where:username=mymainuser]https://myserver.com}</password>
```

Use the syntax 'where:' followed by 'username', 'title', or a 
[custom attribute](https://keepassxc.org/docs/KeePassXC_UserGuide.html#_additional_attributes)
name.

### Other entry values

By default, the password of the KeepassXC is used for the value.  It is possible, however,
to use [custom attributes](https://keepassxc.org/docs/KeePassXC_UserGuide.html#_additional_attributes) 
instead using 'select'.  For example:

```
<password>{[type=keepassxc,select=someCustomAttribute]https://myserver.com}</password>
```

This will make the extension fill this settings.xml server entry's password from Keepass with the
custom attribute 'someCustomAttribute' for `https://myserver.com` instead of its password.

## Configuration

This extension can run without any custom configuration.  However, configuration can be
customized by adding a section to `settings-security.xml` in your `.m2` directory.
Add a configuration XML fragment to settings-security for the keepassxc extension like this:

```
<settingsSecurity>
    ...
    <configurations>
        <configuration>
            <name>keepassxc</name>
            <properties>            
                <property>
                    <name>unlockMaxWaitTime</name>
                    <value>PT20S</value>
                </property>
            </properties>
        </configuration>
    </configurations>
</settingsSecurity>
```

The following properties are supported:

| Property Name           | Description                                                                                                                                                                                                                                                                                                                             | Default                                        |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------|
| unlockMaxWaitTime       | Maximum duration to block builds, wait and prompt the user to open/unlock their database before failing.  Java Duration format.                                                                                                                                                                                                         | PT2M                                           |
| unlockMessageRepeatTime | When waiting for the user to unlock/open the database, repeat the prompt message after this much time.  Java Duration format.                                                                                                                                                                                                           | PT5S                                           |
| credentialsStoreFile    | Where to store the file that holds KeepassXC pairing information.  This is a file path, relative to the .m2 directory.                                                                                                                                                                                                                  | keepassxc-security-maven-extension-credentials |
| failMode                | Either 'EMPTY_PASSWORD' or 'EXCEPTION'.  When 'EMPTY_PASSWORD', if KeepassXC is inaccessible or an entry cannot be found in the Keepass database, the extension will substitute an empty password.  When 'EXCEPTION', the extension will generate an exception which will cause Maven to log an error and leave the entry untranslated. | EMPTY_PASSWORD                                 |

Be aware if failMode is set to EXCEPTION (not the default) and the extension cannot read a password from KeepassXC,
the entry will remain untranslated.  This means for a password of 
`{[type=keepassxc]https://www.myserver.com}` this _literal value_ (including the brackets)
will be sent as the password for a server.  If you are worried about this metadata potentially
being sent to servers which would normally be supplied a password, leave failMode as the default.

## Building

To build the project, run:

```
mvn clean install
```

### Integration Tests

Integration tests are run manually - they require running KeepassXC on your desktop.

- Open the database `itdata/it.kdbx` in KeepassXC, password is 'maventest'
- Build and run the project with the 'keepass-its' profile enabled: `mvn clean install -P keepass-its`
