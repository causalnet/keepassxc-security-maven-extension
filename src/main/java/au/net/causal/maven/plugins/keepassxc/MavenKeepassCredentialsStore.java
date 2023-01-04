package au.net.causal.maven.plugins.keepassxc;

import com.google.common.base.StandardSystemProperty;
import org.purejava.Credentials;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Objects;

public class MavenKeepassCredentialsStore implements KeepassCredentialsStore
{
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
        catch (ClassNotFoundException e)
        {
            throw new IOException("Error deserializing KeepassXC credentials: " + e, e);
        }
    }
}
