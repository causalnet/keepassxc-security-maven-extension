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
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * To use this decrypter when it is registered, use something like the following in <code>settings.xml</code> for encrypted passwords:
 * <p>
 * 
 * <code>{[type=keepassxc]entryName}</code>
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
            Instant connectionMaxTime = connectionStartTime.plus(settings.getUnlockMaxWaitTime());
            Instant lastMessageTime = Instant.EPOCH;
            while (!connected && Instant.now(clock).isBefore(connectionMaxTime))
            {
                Instant now = Instant.now(clock);
                Duration remainingTime = Duration.between(now, connectionMaxTime).truncatedTo(ChronoUnit.SECONDS); //truncate to seconds for a nicer message
                if (lastMessageTime.plus(settings.getUnlockMessageRepeatTime()).isBefore(now))
                {
                    getLogger().info("Waiting for Keepass connection (timeout in " + remainingTime + ")...");
                    lastMessageTime = now;
                }

                Thread.sleep(500L);
                connected = kpa.connectionAvailable();
            }

            if (!connected)
                throw new SecDispatcherException("Failed to connect to Keepass within " + settings.getUnlockMaxWaitTime());
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
                Map<String, ?> results = kpa.getLogins("maven://" + entryName, null, true, List.of(kpa.exportConnection()));
                if (results == null)
                    throw new SecDispatcherException("No KeepassXC entry for " + entryName);

                Object entriesObj = results.get("entries");
                if (!(entriesObj instanceof Collection<?>))
                    throw new SecDispatcherException("No entries value for " + entryName);

                Collection<?> rawEntries = (Collection<?>)entriesObj;
                List<KeepassEntry> entries = new ArrayList<>(rawEntries.size());
                for (Object rawEntry : rawEntries)
                {
                    if (rawEntry instanceof Map<?, ?>)
                        entries.add(KeepassEntry.parse((Map<?, ?>)rawEntry));
                }

                if (entries.isEmpty())
                    throw new SecDispatcherException("No KeepassXC entry for " + entryName);

                KeepassEntry entry = entries.get(0);
                String password = entry.getPassword();
                if (password == null)
                    throw new SecDispatcherException("No KeepassXC entry for " + entryName);

                return password;
            }
            catch (IOException | KeepassProxyAccessException e)
            {
                throw new SecDispatcherException("Error getting entry for " + entryName + ": " + e, e);
            }
        }
        catch (SecDispatcherException e)
        {
            //Only throw ugly stack trace if user has debug mode enabled
            if (getLogger().isDebugEnabled())
                getLogger().error(e.getMessage(), e);
            else
                getLogger().error(e.getMessage());

            return settings.getFailMode().handleKeepassFailure(e);
        }
    }

    /**
     * See:
     * <ul>
     *     <li><a href="https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#get-logins">KeepassXC protocol documentation</a></li>
     *     <li><a href="https://github.com/keepassxreboot/keepassxc/blob/2.7.4/src/browser/BrowserAction.cpp#L234">BrowserAction::handleGetLogins</a></li>
     *     <li><a href="https://github.com/keepassxreboot/keepassxc/blob/2.7.4/src/browser/BrowserService.cpp#L920">BrowserService::prepareEntry</a></li>
     * </ul>
     *
     *
     */
    private static class KeepassEntry
    {
        private final String name;
        private final String login;
        private final String password;
        private final String group;
        private final Map<String, String> stringFields;

        public KeepassEntry(String name, String login, String password, String group, Map<String, String> stringFields)
        {
            this.name = name;
            this.login = login;
            this.password = password;
            this.group = group;
            this.stringFields = Map.copyOf(stringFields);
        }

        public static KeepassEntry parse(Map<?, ?> json)
        {
            String name = stringValue(json.get("name"));
            String login = stringValue(json.get("login"));
            String password = stringValue(json.get("password"));
            String group = stringValue(json.get("group"));

            Object rawStringFields = json.get("stringFields");
            Map<String, String> stringFields = new LinkedHashMap<>();
            if (rawStringFields instanceof Collection<?>)
            {
                Collection<?> stringFieldsList = (Collection<?>)rawStringFields;
                for (Object rawStringFieldEntry : stringFieldsList)
                {
                    if (rawStringFieldEntry instanceof Map<?, ?>)
                    {
                        Map<?, ?> stringFieldEntry = (Map<?, ?>)rawStringFieldEntry;
                        for (Map.Entry<?, ?> e : stringFieldEntry.entrySet())
                        {
                            if (e.getKey() != null && e.getValue() != null)
                                stringFields.put(e.getKey().toString(), e.getValue().toString());
                        }
                    }
                }
            }

            return new KeepassEntry(name, login, password, group, stringFields);
        }

        private static String stringValue(Object raw)
        {
            if (raw == null)
                return null;
            else
                return raw.toString();
        }

        public String getName()
        {
            return name;
        }

        public String getLogin()
        {
            return login;
        }

        public String getPassword()
        {
            return password;
        }

        public String getGroup()
        {
            return group;
        }

        public Map<String, ?> getStringFields()
        {
            return stringFields;
        }
    }
}
