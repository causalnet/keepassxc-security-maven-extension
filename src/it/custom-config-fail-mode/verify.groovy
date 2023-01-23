//Passwords are read by the build from KeepassXC using our extension and written to server-passwords.properties
//This script verifies that the passwords read by Maven were the same as what is in KeepassXC, testing that
//extension is working

File serverPasswordsFile = new File(basedir, 'target/server-passwords.properties')
Properties serverPasswords = new Properties()
serverPasswordsFile.withInputStream {
    serverPasswords.load(it)
}

//failMode is specifically configured to EXCEPTION
//so the password value should remain uninterpreted
assert serverPasswords.entryDoesNotExistInKeepass == '{[type=keepassxc]https://thisisnotinkeepass.test.test.test}'
