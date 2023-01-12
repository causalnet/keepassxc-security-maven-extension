File serverPasswordsFile = new File(basedir, 'target/server-passwords.properties')
Properties serverPasswords = new Properties()
serverPasswordsFile.withInputStream {
    serverPasswords.load(it)
}

assert serverPasswords.readPassword == 'thepassword'
assert serverPasswords.readCustomField == 'customValue1'
assert serverPasswords.filterByUsername1 == 'password1'
assert serverPasswords.filterByUsername2 == 'password2'
assert serverPasswords.filterByTitle1 == 'password1'
assert serverPasswords.filterByTitle3 == 'password3'
assert serverPasswords.filterByCustomField1 == 'password1'
assert serverPasswords.filterByCustomField2 == 'password2'
