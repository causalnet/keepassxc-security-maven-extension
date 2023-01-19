# KeepassXC Security Maven Extension

An extension for Maven that allows it to use KeepassXC to store and retrieve
passwords in `settings.xml` instead of using Maven's built-in password encryption 
mechanism.  It will make Maven act as a client to KeepassXC, similar to how the KeepassXC
browser extension works.

## Requirements

- Maven 3.x
- Java 17 or later (required for Java Unix domain sockets support)
- KeepassXC running on your system

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


## Advanced Usage

### TODO 

## Configuration

### TODO

## Building

To build the project, run:

```
mvn clean install
```

### Integration Tests

Integration tests are run manually - they require running KeepassXC on your desktop.

- Open the database `itdata/it.kdbx` in KeepassXC, password is 'maventest'
- Build and run the project with the 'keepass-its' profile enabled: `mvn clean install -P keepass-its`
