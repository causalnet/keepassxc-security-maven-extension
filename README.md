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
