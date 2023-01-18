//Check that the file downloaded by the dependency plugin using credentials from servers in settings.xml
//that use passwords from KeepassXC actually downloaded correctly
File downloadedFile = new File(basedir, 'target/deps/testdata.txt')
assert downloadedFile.text.trim() == 'This is a text file dependency.'
