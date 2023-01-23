package au.net.causal.maven.plugins.keepassxc;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import org.codehaus.plexus.logging.AbstractLogEnabled;
import org.codehaus.plexus.logging.LogEnabled;
import org.codehaus.plexus.logging.Logger;
import org.codehaus.plexus.personality.plexus.lifecycle.phase.Disposable;
import org.sonatype.plexus.components.sec.dispatcher.PasswordDecryptor;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * A wrapper for another password decryptor that caches decryption results for a certain amount of time.
 */
public class CachingPasswordDecryptor
extends AbstractLogEnabled
implements PasswordDecryptor, Disposable
{
    private final PasswordDecryptor passwordDecryptor;
    private final LoadingCache<DecryptKey, String> passwordCache;

    /**
     * Creates a caching password decryptor.
     *
     * @param passwordDecryptor the underlying decryptor to source passwords from.
     * @param cacheExpireTime amount of time to keep passwords in the cache before expiring them.
     */
    public CachingPasswordDecryptor(PasswordDecryptor passwordDecryptor, Duration cacheExpireTime)
    {
        this.passwordDecryptor = Objects.requireNonNull(passwordDecryptor);
        passwordCache =
            CacheBuilder.newBuilder()
                        .expireAfterAccess(cacheExpireTime.toMillis(), TimeUnit.MILLISECONDS)
                        .build(new CacheLoader<>()
                {
                    @Override
                    public String load(DecryptKey key)
                    throws Exception
                    {
                        return passwordDecryptor.decrypt(key.str, key.attributes, key.config);
                    }
                });
    }

    @Override
    public void enableLogging(Logger theLogger)
    {
        super.enableLogging(theLogger);
        if (passwordDecryptor instanceof LogEnabled)
            ((LogEnabled)passwordDecryptor).enableLogging(theLogger);
    }

    @Override
    public String decrypt(String str, Map attributes, Map config)
    throws SecDispatcherException
    {
        try
        {
            return passwordCache.get(new DecryptKey(str, attributes, config));
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
                throw new UncheckedExecutionException(e);
        }
    }

    @Override
    public void dispose()
    {
        if (passwordDecryptor instanceof Disposable)
            ((Disposable)passwordDecryptor).dispose();
    }

    /**
     * Cache key for a settings.xml server entry that requires decryption.
     */
    protected static class DecryptKey
    {
        private final String str;
        private final Map<?, ?> attributes;
        private final Map<?, ?> config;

        public DecryptKey(String str, Map<?, ?> attributes, Map<?, ?> config)
        {
            this.str = str;
            this.attributes = attributes;
            this.config = config;
        }

        @Override
        public boolean equals(Object o)
        {
            if (this == o) return true;
            if (!(o instanceof DecryptKey that)) return false;
            return Objects.equals(str, that.str) &&
                   Objects.equals(attributes, that.attributes) &&
                   Objects.equals(config, that.config);
        }

        @Override
        public int hashCode()
        {
            return Objects.hash(str, attributes, config);
        }

        @Override
        public String toString()
        {
            return new StringJoiner(", ", DecryptKey.class.getSimpleName() + "[", "]")
                    .add("str='" + str + "'")
                    .add("attributes=" + attributes)
                    .add("config=" + config)
                    .toString();
        }
    }
}
