package au.net.causal.maven.plugins.keepassxc;

import org.purejava.Credentials;
import org.codehaus.plexus.logging.Logger;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Objects;

/**
 * Stores credentials as a serialized credentials object, the same as how the
 */
public class MavenKeepassCredentialsStore implements KeepassCredentialsStore
{
    private final Path storeFile;
    private final Logger log;

    public MavenKeepassCredentialsStore(Path storeFile, Logger log)
    {
        this.storeFile = Objects.requireNonNull(storeFile);
        this.log = Objects.requireNonNull(log);
    }

    @Override
    public void saveCredentials(Credentials credentials)
    throws IOException
    {
        Files.createDirectories(storeFile.getParent());
        Path tmpPath = storeFile.resolveSibling(storeFile.getFileName() + ".tmp");
        try (ObjectOutputStream os = new ObjectOutputStream(Files.newOutputStream(tmpPath)))
        {
            os.writeObject(credentials);
        }
        Files.move(tmpPath, storeFile, StandardCopyOption.REPLACE_EXISTING);
    }

    @Override
    public Credentials loadCredentials()
    throws IOException
    {
        if (Files.notExists(storeFile))
            return null;

        try (ObjectInputStream is = new ObjectInputStream(Files.newInputStream(storeFile)))
        {
            return (Credentials)is.readObject();
        }
        catch (ObjectStreamException | ClassNotFoundException e)
        {
            //If the file is corrupted (empty or bad data) log a warning and just re-pair with Keepass
            log.error("Keepass Maven extension credentials file corrupted - will attempt recreation and repair with KeepassXC: " + e, e);
            return null;
        }
        //Normal IO exception will fail like normal - a more serious data reading issue
    }
}
