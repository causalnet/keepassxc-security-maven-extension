package au.net.causal.maven.plugins.keepassxc;

import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.logging.AbstractLogEnabled;
import org.sonatype.plexus.components.sec.dispatcher.PasswordDecryptor;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import java.util.Map;

/**
 * To use this decrypter when it is registered, use something like the following in <code>settings.xml</code> for encrypted passwords:
 * <p>
 * 
 * <code>{[type=keepassxc]entryName}</code>
 * 
 * @author prunge
 */
@Component(role= PasswordDecryptor.class, hint="keepassxc")
public class KeepassXcPasswordDecrypter
extends AbstractLogEnabled
implements PasswordDecryptor
{
    @Override
    public String decrypt(String str, Map attributes, Map config)
    throws SecDispatcherException
    {
        String entryName = str;
        getLogger().info("Need to grab entry '" + entryName + "' from KeepassXC");

        //TODO
        return "password-from-keepassxc";
    }
}
