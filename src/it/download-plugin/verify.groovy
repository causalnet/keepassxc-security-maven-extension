//Check that the file downloaded by the download plugin using credentials from servers in settings.xml
//that use passwords from KeepassXC actually downloaded correctly
File downloadedFile = new File(basedir, 'target/myfile.txt')
assert downloadedFile.text.trim() == 'This file was downloaded from the test server.'
