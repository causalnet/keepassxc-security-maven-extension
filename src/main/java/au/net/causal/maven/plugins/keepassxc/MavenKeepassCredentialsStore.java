package au.net.causal.maven.plugins.keepassxc;

import com.google.common.base.StandardSystemProperty;
import org.purejava.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Objects;

public class MavenKeepassCredentialsStore implements KeepassCredentialsStore
{
    private static final Logger log = LoggerFactory.getLogger(MavenKeepassCredentialsStore.class);

    private final Path storeFile;

    public MavenKeepassCredentialsStore()
    {
        this(Path.of(StandardSystemProperty.USER_HOME.value(), ".m2", "keepassxc-security-maven-extension-credentials"));
    }

    public MavenKeepassCredentialsStore(Path storeFile)
    {
        this.storeFile = Objects.requireNonNull(storeFile);
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
