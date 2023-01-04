package au.net.causal.maven.plugins.keepassxc;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import org.codehaus.plexus.logging.AbstractLogEnabled;
import org.codehaus.plexus.logging.LogEnabled;
import org.codehaus.plexus.logging.Logger;
import org.sonatype.plexus.components.sec.dispatcher.PasswordDecryptor;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * A wrapper for another password decrypter that caches decryption results for a certain amount of time.
 */
public class CachingPasswordDecrypter
extends AbstractLogEnabled
implements PasswordDecryptor
{
    private final PasswordDecryptor passwordDecryptor;
    private final LoadingCache<String, String> passwordCache;

    public CachingPasswordDecrypter(PasswordDecryptor passwordDecryptor, Duration cacheExpireTime)
    {
        this.passwordDecryptor = Objects.requireNonNull(passwordDecryptor);
        passwordCache =
            CacheBuilder.newBuilder()
                        .expireAfterAccess(cacheExpireTime.toMillis(), TimeUnit.MILLISECONDS)
                        .build(new CacheLoader<>()
                {
                    @Override
                    public String load(String key)
                    throws Exception
                    {
                        return passwordDecryptor.decrypt(key, Map.of(), Map.of());
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
            return passwordCache.get(str);
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
}
