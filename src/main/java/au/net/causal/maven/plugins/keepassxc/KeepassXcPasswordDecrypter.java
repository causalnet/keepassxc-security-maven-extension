package au.net.causal.maven.plugins.keepassxc;

import au.net.causal.maven.plugins.keepassxc.connection.KeepassProxy;
import com.google.common.base.StandardSystemProperty;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.codehaus.plexus.logging.AbstractLogEnabled;
import org.codehaus.plexus.personality.plexus.lifecycle.phase.Disposable;
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
import java.util.Objects;
import java.util.concurrent.ExecutionException;

/**
 * A password decryptor that reads passwords from a paired KeepassXC instance running on the user's system.
 * <p>
 *
 * To use this decrypter when it is registered, use something like the following in <code>settings.xml</code> for encrypted passwords:
 * <p>
 * 
 * <code>{[type=keepassxc]entryName}</code>
 * <p>
 *
 * This decryptor is not registered with the Plexus container, but a {@linkplain CachingKeepassXcPasswordDecrypter caching wrapper} is.
 */
public class KeepassXcPasswordDecrypter
extends AbstractLogEnabled
implements PasswordDecryptor, Disposable
{
    private static final Path CREDENTIALS_STORE_BASE_DIRECTORY = Path.of(StandardSystemProperty.USER_HOME.value(), ".m2");

    private final Clock clock = Clock.systemUTC();

    /**
     * A cache with Decrypter config keys (the map sent from Maven in {@link #decrypt(String, Map, Map)}) and proxy values.  This is used to
     * re-use KeepassXC connections and not constantly re-authenticate every time Maven asks for a single password.
     */
    private final LoadingCache<Map<?, ?>, KeepassProxy> proxyCacheByConfig;

    public KeepassXcPasswordDecrypter()
    {
        proxyCacheByConfig =
                CacheBuilder.newBuilder()
                    .<Map<?, ?>, KeepassProxy>removalListener(notification -> notification.getValue().close())
                    .build(new CacheLoader<>()
                    {
                        @Override
                        public KeepassProxy load(Map<?, ?> config)
                        throws Exception
                        {
                            return connectKeepassProxy(config);
                        }
                    });
    }

    /**
     * Creates a new connection to KeepassXC.
     *
     * @param config configuration from settings-security.xml for the decryptor.  Might be empty.
     *
     * @return a new Keepass proxy connection.
     *
     * @throws SecDispatcherException if an error occurs making the connection.
     */
    private KeepassProxy connectKeepassProxy(Map<?, ?> config)
    throws SecDispatcherException
    {
        if (config == null)
            config = Map.of();
        else
            config = Map.copyOf(config);

        KeepassExtensionSettings settings = new KeepassExtensionSettings();
        settings.configure(config);

        KeepassCredentialsStore credentialsStore = createCredentialsStore(settings);

        return connectKeepassProxy(credentialsStore, settings);
    }

    /**
     * Creates a new connection to KeepassXC given some extension settings.
     *
     * @param settings configuration for the decryptor.  Basically a type-safe version of the configuration passed from Maven, sourced from settings-security.xml.
     *
     * @return a new Keepass proxy connection.
     *
     * @throws SecDispatcherException if an error occurs making the connection.
     */
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


        tryRepeat(settings,
                  "Maven needs to read passwords from KeepassXC, please start KeepassXC, ensure the 'Browser Extensions' option is enabled and open your database",
                  "Failed to connect to KeepassXC",
                  () ->
        {
            try
            {
                kpa.connect();
            }
            catch (IOException e)
            {
                throw new SecDispatcherException("Failed to connect to KeepassXC: " + e.getMessage(), e);
            }
        });

        boolean connected = kpa.connectionAvailable();
        if (!connected)
            connected = kpa.associate();

        tryRepeat(settings,
                  "Maven needs to read passwords from KeepassXC, please unlock your database",
                  "Failed to connect to KeepassXC",
                  () ->
        {
            boolean iConnected = kpa.connectionAvailable();
            if (!iConnected)
                throw new SecDispatcherException("Could not connect to KeepassXC");
        });

        return kpa;
    }

    /**
     * Runs a block of code multiple times until it succeeds or the unlock timeout it hit.  Non-success for the block is when it fails
     * with a SecDispatcherException.
     * <p>
     *
     * This method returns normally if, either initially or during a repeat, the code block succeeds.  If it times out, a
     * SecDispatcherException is thrown.
     *
     * @param settings Keepass settings used to determine the timeout time and the message repeat time.
     * @param failMessage message to display and possibly repeat to the user when the code block fails.
     * @param timeoutMessage message to display on timeout.
     * @param block the code block to execute, possibly multiple times.
     *
     * @throws SecDispatcherException if the block never once succeeded and the timeout time is exceeded.
     */
    private void tryRepeat(KeepassExtensionSettings settings, String failMessage, String timeoutMessage, RepeatBlock block)
    throws SecDispatcherException
    {
        SecDispatcherException failureException = null;

        //Staggered
        Instant connectionStartTime = Instant.now(clock);
        Instant connectionMaxTime = connectionStartTime.plus(settings.getUnlockMaxWaitTime());
        Instant lastMessageTime = Instant.EPOCH;
        while (failureException == null || Instant.now(clock).isBefore(connectionMaxTime))
        {
            try
            {
                block.call();

                //If we succeed we are finished
                return;
            }
            catch (SecDispatcherException e)
            {
                failureException = e;
            }

            //If we get here we failed to connect
            Instant now = Instant.now(clock);
            Duration remainingTime = Duration.between(now, connectionMaxTime).truncatedTo(ChronoUnit.SECONDS); //truncate to seconds for a nicer message
            if (lastMessageTime.plus(settings.getUnlockMessageRepeatTime()).isBefore(now))
            {
                getLogger().info(failMessage + " (timeout in " + remainingTime + ")...");
                lastMessageTime = now;
            }

            try
            {
                Thread.sleep(500L);
            }
            catch (InterruptedException e)
            {
                throw new SecDispatcherException("Interrupted while waiting for KeepassXC", e);
            }
        }

        throw new SecDispatcherException(timeoutMessage + " (within " + settings.getUnlockMaxWaitTime() + ")");
    }

    /**
     * Loads the credentials/pairing store for our KeepassXC client.  The credentials from this store are used for pairing with KeepassXC as a client.
     *
     * @param settings settings that specify where the credentials store exists.
     *
     * @return the store.
     */
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
        else
            config = Map.copyOf(config);

        KeepassExtensionSettings settings = new KeepassExtensionSettings();
        settings.configure(config);

        try
        {
            KeepassProxy kpa;
            try
            {
                kpa = proxyCacheByConfig.get(config);
            }
            catch (ExecutionException e)
            {
                if (e.getCause() instanceof SecDispatcherException)
                    throw (SecDispatcherException)e.getCause();
                else if (e.getCause() instanceof RuntimeException)
                    throw (RuntimeException)e.getCause();
                else if (e.getCause() instanceof Error)
                    throw (Error)e.getCause();
                else
                    throw new RuntimeException(e);
            }

            String entryName = str;
            getLogger().debug("Need to read entry '" + entryName + "' from KeepassXC");

            try
            {
                Map<String, ?> results = kpa.getLogins(entryName, null, true, List.of(kpa.exportConnection()));
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

                KeepassEntry entry = selectEntry(entries, attributes);
                if (entry == null)
                    throw new SecDispatcherException("No KeepassXC entry for " + entryName);

                String value = selectEntryValue(entry, attributes);
                if (value == null)
                    throw new SecDispatcherException("No KeepassXC entry value for " + entryName);

                return value;
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
     * Given a number of matching entries from Keepass, select one of them based on any selection criteria in the decrypter entry attributes.
     *
     * @param entries entries that Keepass returned.
     * @param decrypterEntryAttributes attributes from the decrypter entry in settings.xml.
     *
     * @return the selected entry, or null if nothing matched.
     *
     * @throws SecDispatcherException if an error occurs.
     */
    protected KeepassEntry selectEntry(Collection<? extends KeepassEntry> entries, Map<?, ?> decrypterEntryAttributes)
    throws SecDispatcherException
    {
        if (entries.isEmpty())
            return null;

        List<? extends EntryFilter> filters = filtersFromDecrypterEntryAttributes(decrypterEntryAttributes);

        return entries.stream().filter(entry ->
        {
            for (EntryFilter filter : filters)
            {
                String entryValue = selectEntryValue(entry, filter.getKey());
                if (!Objects.equals(entryValue, filter.getValue()))
                    return false;
            }

            return true;
        }).findFirst().orElse(null);
    }

    /**
     * Creates filters from attributes configured on a decrypter entry.
     * <p>
     *
     * Filter attributes are in the form "where:[field]=[value]", so for example in the entry:
     * <pre>
     *     {[type=keepassxc,where:username=user1]https://example.com}
     * </pre>
     * a single filter that ensures an entry's username is 'user1' will be returned.
     *
     * @param decrypterEntryAttributes attributes from the decrypter entry.
     *
     * @return a list of filters, possibly empty if there are no filter attributes.
     */
    private List<? extends EntryFilter> filtersFromDecrypterEntryAttributes(Map<?, ?> decrypterEntryAttributes)
    {
        List<EntryFilter> filters = new ArrayList<>();
        for (Map.Entry<?, ?> attributeEntry : decrypterEntryAttributes.entrySet())
        {
            if (attributeEntry.getKey() instanceof String && attributeEntry.getValue() != null)
            {
                String attributeKey = (String)attributeEntry.getKey();
                if (attributeKey.startsWith("where:"))
                    filters.add(new EntryFilter(attributeKey.substring("where:".length()), attributeEntry.getValue().toString()));
            }
        }
        return filters;
    }

    /**
     * From an entry, determine the string value to return from it based on decrypter entry attributes.  Allows selection of different values, such as login, password or
     * custom attributes.
     *
     * @param entry the Keepass entry.
     * @param decrypterEntryAttributes attributes from the decrypter entry in settings.xml.
     *
     * @return the value to use, or null if there was none on this entry.
     *
     * @throws SecDispatcherException if an error occurs.
     */
    protected String selectEntryValue(KeepassEntry entry, Map<?, ?> decrypterEntryAttributes)
    throws SecDispatcherException
    {
        String select = stringValue(decrypterEntryAttributes.get("select"));
        return selectEntryValue(entry, select);
    }

    /**
     * From an entry, determine the string value to return from it based on a select string.  Allows selection of different values, such as login, password or
     * custom attributes.
     *
     * @param entry the Keepass entry.
     * @param selectAttribute the 'select' attribute used for selecting a field.
     *
     * @return the value to use, or null if there was none on this entry.
     */
    private String selectEntryValue(KeepassEntry entry, String selectAttribute)
    {
        //The values for 'select' should be similar or equal to the ones in KeepassXC UI to make it least confusing for users
        if (selectAttribute == null || "password".equals(selectAttribute))
            return entry.getPassword();
        else if ("username".equals(selectAttribute))
            return entry.getLogin();
        else if ("title".equals(selectAttribute))
            return entry.getName();
        else //Custom attribute
        {
            String customFieldValue = stringValue(entry.getStringFields().get(selectAttribute));

            //Try with 'KPH: ' prefix - Keepass wants custom fields that come through the browser helper to be prefixed by this anyway
            //but we don't want to burden the Maven users with having to specify this on every custom attribute
            if (customFieldValue == null)
                customFieldValue = stringValue(entry.getStringFields().get("KPH: " + selectAttribute));

            return customFieldValue;
        }
    }

    /**
     * Converts object to string, keeping null as null.
     */
    private static String stringValue(Object raw)
    {
        if (raw == null)
            return null;
        else
            return raw.toString();
    }

    @Override
    public void dispose()
    {
        //Close any KeepassXC connections that are maintained in the cache
        proxyCacheByConfig.invalidateAll();
    }

    /**
     * An entry returned from KeepassXC.
     *
     * See:
     * <ul>
     *     <li><a href="https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#get-logins">KeepassXC protocol documentation</a></li>
     *     <li><a href="https://github.com/keepassxreboot/keepassxc/blob/2.7.4/src/browser/BrowserAction.cpp#L234">BrowserAction::handleGetLogins</a></li>
     *     <li><a href="https://github.com/keepassxreboot/keepassxc/blob/2.7.4/src/browser/BrowserService.cpp#L920">BrowserService::prepareEntry</a></li>
     * </ul>
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

        /**
         * Parses an entry from JSON returned from a KeepassXC connection's getLogin call.
         *
         * @param json raw JSON in map form.  Nested maps, strings and primitives.
         *
         * @return the parsed entry.
         */
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

    /**
     * KeepassXC entry filter that may be used on a password entry in settings.xml.  If multiple KeepassXC entries match a URL, these filters may be
     * specified by the user to pick specific entries, such as by username or by custom attribute.
     */
    private static class EntryFilter
    {
        private final String key;
        private final String value;

        public EntryFilter(String key, String value)
        {
            this.key = key;
            this.value = value;
        }

        public String getKey()
        {
            return key;
        }

        public String getValue()
        {
            return value;
        }

        @Override
        public String toString()
        {
            return getKey() + "=" + getValue();
        }
    }

    /**
     * Piece of KeypassXC connection code that can potentially be repeated if it fails.
     */
    @FunctionalInterface
    private static interface RepeatBlock
    {
        /**
         * Executes the code block.  Returns normally when successful, or throws a SecDispatcherException on failure.
         *
         * @throws SecDispatcherException on failure.
         */
        public void call()
        throws SecDispatcherException;
    }
}
