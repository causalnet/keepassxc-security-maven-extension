package au.net.causal.maven.plugins.keepassxc;

import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.logging.AbstractLogEnabled;
import org.purejava.KeepassProxyAccess;
import org.purejava.KeepassProxyAccessException;
import org.sonatype.plexus.components.sec.dispatcher.PasswordDecryptor;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
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
    private KeepassProxy connectKeepassProxy()
    throws SecDispatcherException
    {
        KeepassProxy kpa;
        try
        {
            kpa = new KeepassProxy(new MavenKeepassCredentialsStore());
        }
        catch (IOException e)
        {
            throw new SecDispatcherException("Error initializing Keepass proxy: " + e, e);
        }

        try
        {
            kpa.connect();
        }
        catch (IOException e)
        {
            throw new SecDispatcherException("Failed to connect to keepass", e);
        }

        boolean connected = kpa.connectionAvailable();
        if (!connected)
            connected = kpa.associate();

        try
        {
            while (!connected)
            {
                getLogger().info("Waiting for Keepass connection...");
                Thread.sleep(1000L);
                connected = kpa.connectionAvailable();
            }
        }
        catch (InterruptedException e)
        {
            throw new SecDispatcherException("Interrupted while waiting for KeepassXC", e);
        }

        return kpa;
    }

    private KeepassProxyAccess connectKeepassOrig()
    throws SecDispatcherException
    {
        var kpa = new KeepassProxyAccess();
        boolean ok = kpa.connect();
        if (!ok)
            throw new RuntimeException("Failed to connect to keepass");

        String associateId = kpa.getAssociateId();
        String associateKey = kpa.getIdKeyPairPublicKey();

        //System.out.println(associateId + "/" + associateKey);

        boolean associated = kpa.testAssociate(associateId, associateKey);

        if (!associated)
        {
            associated = kpa.associate();
            //if (!associated)
            //    throw new RuntimeException("Failed to associate");
        }

        //System.out.println(kpa);

        associateId = kpa.getAssociateId();
        associateKey = kpa.getIdKeyPairPublicKey();

        //System.out.println("ID: " + associateId + ": " + associateKey);

        try
        {
            while (!associated)
            {
                associateId = kpa.getAssociateId();
                associateKey = kpa.getIdKeyPairPublicKey();

                getLogger().info("Waiting for assoc " + associateId + "/" + associateKey);
                associated = kpa.testAssociate(associateId, associateKey);
                Thread.sleep(1000L);
            }
        }
        catch (InterruptedException e)
        {
            throw new SecDispatcherException("Interrupted while waiting for KeepassXC", e);
        }

        return kpa;
    }

    @Override
    public String decrypt(String str, Map attributes, Map config)
    throws SecDispatcherException
    {
        try (var kpa = connectKeepassProxy())
        {
            String entryName = str;
            getLogger().info("Need to grab entry '" + entryName + "' from KeepassXC");

            try
            {
                var results = kpa.getLogins("maven://" + entryName, null, true, List.of(kpa.exportConnection()));
                if (results == null)
                    throw new SecDispatcherException("No KeepassXC entry for " + entryName);

                String password = nestedMapValue(results, "entries", "password");
                if (password == null)
                    throw new SecDispatcherException("No KeepassXC entry for " + entryName);

                return password;
            }
            catch (IOException | KeepassProxyAccessException e)
            {
                throw new SecDispatcherException("Error getting entry for " + entryName + ": " + e, e);
            }
        }
    }

    private static String nestedMapValue(Map<?, ?> map, String... path)
    {
        return nestedMapValue(map, List.of(path));
    }

    private static String nestedMapValue(Map<?, ?> map, List<String> path)
    {
        String key = path.get(0);
        Object value = map.get(key);
        if (value == null)
            return null;

        //Unwrap collections - just use first element
        if (value instanceof Collection<?>)
        {
            Collection<?> cValue = (Collection<?>)value;
            if (!cValue.isEmpty())
                value = cValue.iterator().next();
        }

        if (path.size() == 1) //Last key
            return value.toString();
        else if (value instanceof Map<?, ?>)
            return nestedMapValue((Map<?, ?>)value, path.subList(1, path.size()));
        else
            return null;
    }
}
