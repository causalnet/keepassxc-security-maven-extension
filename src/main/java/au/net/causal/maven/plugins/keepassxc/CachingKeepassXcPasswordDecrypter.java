package au.net.causal.maven.plugins.keepassxc;

import org.codehaus.plexus.component.annotations.Component;
import org.sonatype.plexus.components.sec.dispatcher.PasswordDecryptor;

import java.time.Duration;

@Component(role= PasswordDecryptor.class, hint="keepassxc")
public class CachingKeepassXcPasswordDecrypter extends CachingPasswordDecrypter
{
    public CachingKeepassXcPasswordDecrypter()
    {
        super(new KeepassXcPasswordDecrypter(), Duration.ofMinutes(1L));
    }
}
