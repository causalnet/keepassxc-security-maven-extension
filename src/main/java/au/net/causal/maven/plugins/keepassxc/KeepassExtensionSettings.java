package au.net.causal.maven.plugins.keepassxc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Map;

public class KeepassExtensionSettings
{
    private static final Logger log = LoggerFactory.getLogger(KeepassExtensionSettings.class);

    private static final String CONFIG_KEY_CREDENTIALS_STORE_FILE = "credentialsStoreFile";
    private static final String CONFIG_KEY_KEEPASS_UNLOCK_MAX_WAIT_TIME = "keepassUnlockMaxWaitTime";

    private Path credentialsStoreFile = Path.of("keepassxc-security-maven-extension-credentials");
    private Duration keepassUnlockMaxWaitTime = Duration.ofMinutes(2L);

    public void configure(Map<?, ?> config)
    {
        Path credentialsStoreFile = pathFromMapKey(config, CONFIG_KEY_CREDENTIALS_STORE_FILE);
        if (credentialsStoreFile != null)
            setCredentialsStoreFile(credentialsStoreFile);

        Duration keepassUnlockMaxWaitTime = durationFromMapKey(config, CONFIG_KEY_KEEPASS_UNLOCK_MAX_WAIT_TIME);
        if (keepassUnlockMaxWaitTime != null)
            setKeepassUnlockMaxWaitTime(keepassUnlockMaxWaitTime);
    }

    private static String stringFromMapKey(Map<?, ?> map, String key)
    {
        Object value = map.get(key);
        if (value == null)
            return null;
        else
            return value.toString();
    }

    private static Path pathFromMapKey(Map<?, ?> map, String key)
    {
        String sValue = stringFromMapKey(map, key);
        if (sValue == null)
            return null;
        else
            return Path.of(sValue);
    }

    private static Duration durationFromMapKey(Map<?, ?> map, String key)
    {
        String sValue = stringFromMapKey(map, key);
        if (sValue == null)
            return null;
        else
        {
            try
            {
                return Duration.parse(sValue);
            }
            catch (DateTimeParseException e)
            {
                log.warn("Error parsing Keepass extension configuration option '" + key + "': " + e, e);
                return null;
            }
        }
    }

    public Path getCredentialsStoreFile()
    {
        return credentialsStoreFile;
    }

    public void setCredentialsStoreFile(Path credentialsStoreFile)
    {
        this.credentialsStoreFile = credentialsStoreFile;
    }

    public Duration getKeepassUnlockMaxWaitTime()
    {
        return keepassUnlockMaxWaitTime;
    }

    public void setKeepassUnlockMaxWaitTime(Duration keepassUnlockMaxWaitTime)
    {
        this.keepassUnlockMaxWaitTime = keepassUnlockMaxWaitTime;
    }
}
