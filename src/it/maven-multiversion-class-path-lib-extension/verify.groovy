//Passwords are read by the build from KeepassXC using our extension and written to server-passwords.properties
//This script verifies that the passwords read by Maven were the same as what is in KeepassXC, testing that
//extension is working

['3.9.1', '3.8.7', '3.6.3' , '3.5.4', '3.3.9'].each { mavenVersion ->

    File serverPasswordsFile = new File(basedir, "target/server-passwords-${mavenVersion}.properties")
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

    //failMode is EMPTY_PASSWORD by default
    assert serverPasswords.entryDoesNotExistInKeepass == ''
}

return
