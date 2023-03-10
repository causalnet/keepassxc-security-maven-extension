package au.net.causal.maven.plugins.keepassxc;

import org.codehaus.plexus.component.annotations.Component;
import org.sonatype.plexus.components.sec.dispatcher.PasswordDecryptor;

import java.time.Duration;

/**
 * KeepassXC password decryptor that caches passwords read from KeepassXC to avoid rereading.
 */
@Component(role= PasswordDecryptor.class, hint="keepassxc")
public class CachingKeepassXcPasswordDecryptor extends CachingPasswordDecryptor
{
    public CachingKeepassXcPasswordDecryptor()
    {
        super(new KeepassXcPasswordDecryptor(), Duration.ofMinutes(1L));
    }
}
