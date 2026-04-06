package au.net.causal.maven.plugins.keepassxc;

import com.google.inject.Provider;
import org.sonatype.plexus.components.sec.dispatcher.PasswordDecryptor;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

@Singleton
@Named("keepassxc")
public class KeepassPasswordDecryptorProvider implements Provider<PasswordDecryptor>
{
    private final CachingKeepassXcPasswordDecryptor instance;

    @Inject
    public KeepassPasswordDecryptorProvider()
    {
        instance = new CachingKeepassXcPasswordDecryptor();
    }

    @Override
    public PasswordDecryptor get()
    {
        return instance;
    }
}
