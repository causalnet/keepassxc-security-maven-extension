package au.net.causal.maven.plugins.keepassxc;

import au.net.causal.maven.plugins.keepassxc.connection.KeepassProxy;
import com.google.common.base.StandardSystemProperty;
import org.codehaus.plexus.logging.AbstractLogEnabled;
import org.purejava.KeepassProxyAccessException;
import org.sonatype.plexus.components.sec.dispatcher.PasswordDecryptor;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * To use this decrypter when it is registered, use something like the following in <code>settings.xml</code> for encrypted passwords:
 * <p>
 * 
 * <code>{[type=keepassxc]entryName}</code>
 * 
 * @author prunge
 */
public class KeepassXcPasswordDecrypter
extends AbstractLogEnabled
implements PasswordDecryptor
{
    private static final Path CREDENTIALS_STORE_BASE_DIRECTORY = Path.of(StandardSystemProperty.USER_HOME.value(), ".m2");

    private final Clock clock = Clock.systemUTC();

    private KeepassProxy connectKeepassProxy(KeepassCredentialsStore credentialsStore, KeepassExtensionSettings settings)
    throws SecDispatcherException
    {
        KeepassProxy kpa;
        try
        {
            kpa = new KeepassProxy(credentialsStore);
        }
        catch (IOException e)
        {
            SecDispatcherException ex = new SecDispatcherException("Error initializing Keepass proxy: " + e, e);
            getLogger().error(ex.getMessage(), ex);
            throw ex;
        }

        try
        {
            kpa.connect();
        }
        catch (IOException e)
        {
            SecDispatcherException ex = new SecDispatcherException("Failed to connect to keepass", e);
            getLogger().error(ex.getMessage(), ex);
            throw ex;
        }

        boolean connected = kpa.connectionAvailable();
        if (!connected)
            connected = kpa.associate();

        try
        {
            //Always do first attempt - at the moment associate() always returns false to work around a bug in KeepassXC
            connected = kpa.connectionAvailable();

            Instant connectionStartTime = Instant.now(clock);
            Instant connectionMaxTime = connectionStartTime.plus(settings.getKeepassUnlockMaxWaitTime());
            while (!connected && Instant.now(clock).isBefore(connectionMaxTime))
            {
                Duration remainingTime = Duration.between(Instant.now(clock), connectionMaxTime).truncatedTo(ChronoUnit.SECONDS); //truncate to seconds for a nicer message
                getLogger().info("Waiting for Keepass connection (timeout in " + remainingTime + ")...");
                Thread.sleep(1000L);
                connected = kpa.connectionAvailable();
            }

            if (!connected)
            {
                getLogger().error("Failed to connect to Keepass within " + settings.getKeepassUnlockMaxWaitTime());
                throw new SecDispatcherException("Failed to connect to Keepass within " + settings.getKeepassUnlockMaxWaitTime());
            }
        }
        catch (InterruptedException e)
        {
            throw new SecDispatcherException("Interrupted while waiting for KeepassXC", e);
        }

        return kpa;
    }

    protected KeepassCredentialsStore createCredentialsStore(KeepassExtensionSettings settings)
    {
        //May be absolute, but if relative resolve from the .m2 directory
        Path credentialsStoreFile = CREDENTIALS_STORE_BASE_DIRECTORY.resolve(settings.getCredentialsStoreFile());

        return new MavenKeepassCredentialsStore(credentialsStoreFile);
    }

    @Override
    public String decrypt(String str, Map attributes, Map config)
    throws SecDispatcherException
    {
        if (config == null)
            config = Map.of();

        KeepassExtensionSettings settings = new KeepassExtensionSettings();
        settings.configure(config);

        KeepassCredentialsStore credentialsStore = createCredentialsStore(settings);

        try (KeepassProxy kpa = connectKeepassProxy(credentialsStore, settings))
        {
            String entryName = str;
            getLogger().info("Need to grab entry '" + entryName + "' from KeepassXC");

            try
            {
                var results = kpa.getLogins("maven://" + entryName, null, true, List.of(kpa.exportConnection()));
                if (results == null)
                    throw new SecDispatcherException("No KeepassXC entry for " + entryName);

                String password = nestedMapValue(results, "entries", "password");
                if (password == null)
                    throw new SecDispatcherException("No KeepassXC entry for " + entryName);

                return password;
            }
            catch (IOException | KeepassProxyAccessException e)
            {
                throw new SecDispatcherException("Error getting entry for " + entryName + ": " + e, e);
            }
        }
    }

    private static String nestedMapValue(Map<?, ?> map, String... path)
    {
        return nestedMapValue(map, List.of(path));
    }

    private static String nestedMapValue(Map<?, ?> map, List<String> path)
    {
        String key = path.get(0);
        Object value = map.get(key);
        if (value == null)
            return null;

        //Unwrap collections - just use first element
        if (value instanceof Collection<?>)
        {
            Collection<?> cValue = (Collection<?>)value;
            if (!cValue.isEmpty())
                value = cValue.iterator().next();
        }

        if (path.size() == 1) //Last key
            return value.toString();
        else if (value instanceof Map<?, ?>)
            return nestedMapValue((Map<?, ?>)value, path.subList(1, path.size()));
        else
            return null;
    }
}
