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
    private static final String CONFIG_KEY_UNLOCK_MAX_WAIT_TIME = "unlockMaxWaitTime";
    private static final String CONFIG_KEY_UNLOCK_MESSAGE_REPEAT_TIME = "unlockMessageRepeatTime";
    private static final String CONFIG_KEY_FAIL_MODE = "failMode";

    private Path credentialsStoreFile = Path.of("keepassxc-security-maven-extension-credentials");
    private Duration unlockMaxWaitTime = Duration.ofMinutes(2L);
    private Duration unlockMessageRepeatTime = Duration.ofSeconds(5L);

    //Default failure mode to empty_password since throwing an exception will make Maven deliver the settings password string uninterpreted, potentially exposing to a remote site
    //a bit of information about the local user's setup
    private FailMode failMode = FailMode.EMPTY_PASSWORD;

    public void configure(Map<?, ?> config)
    {
        Path credentialsStoreFile = pathFromMapKey(config, CONFIG_KEY_CREDENTIALS_STORE_FILE);
        if (credentialsStoreFile != null)
            setCredentialsStoreFile(credentialsStoreFile);

        Duration unlockMaxWaitTime = durationFromMapKey(config, CONFIG_KEY_UNLOCK_MAX_WAIT_TIME);
        if (unlockMaxWaitTime != null)
            setUnlockMaxWaitTime(unlockMaxWaitTime);

        Duration unlockMessageRepeatTime = durationFromMapKey(config, CONFIG_KEY_UNLOCK_MESSAGE_REPEAT_TIME);
        if (unlockMessageRepeatTime != null)
            setUnlockMessageRepeatTime(unlockMessageRepeatTime);

        FailMode failMode = enumFromMapKey(config, CONFIG_KEY_FAIL_MODE, FailMode.class);
        if (failMode != null)
            setFailMode(failMode);
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
                log.error("Error parsing Keepass extension configuration option '" + key + "' (" + sValue + "): " + e, e);
                return null;
            }
        }
    }

    private static <E extends Enum<E>> E enumFromMapKey(Map<?, ?> map, String key, Class<E> enumType)
    {
        String sValue = stringFromMapKey(map, key);
        if (sValue == null)
            return null;
        else
        {
            try
            {
                return Enum.valueOf(enumType, sValue);
            }
            catch (IllegalArgumentException e)
            {
                log.error("Error parsing Keepass extension configuration option '" + key + "' (" + sValue + "): " + e, e);
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

    public Duration getUnlockMaxWaitTime()
    {
        return unlockMaxWaitTime;
    }

    public void setUnlockMaxWaitTime(Duration unlockMaxWaitTime)
    {
        this.unlockMaxWaitTime = unlockMaxWaitTime;
    }

    public Duration getUnlockMessageRepeatTime()
    {
        return unlockMessageRepeatTime;
    }

    public void setUnlockMessageRepeatTime(Duration unlockMessageRepeatTime)
    {
        this.unlockMessageRepeatTime = unlockMessageRepeatTime;
    }

    public FailMode getFailMode()
    {
        return failMode;
    }

    public void setFailMode(FailMode failMode)
    {
        this.failMode = failMode;
    }
}
