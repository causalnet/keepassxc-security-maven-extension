package au.net.causal.maven.plugins.keepassxc.connection;

import au.net.causal.maven.plugins.keepassxc.KeepassCredentialsStore;
import org.apache.commons.lang3.SystemUtils;
import org.keepassxc.Connection;
import org.purejava.Credentials;
import org.purejava.KeepassProxyAccessException;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Replacement for KeepassProxyAccess that saves configuration in a way more suitable for a Maven extension.
 *
 * @see org.purejava.KeepassProxyAccess
 */
public class KeepassProxy implements AutoCloseable
{
    private final Connection connection;
    private final KeepassCredentialsStore credentialsStore;
    private final CredentialsUpdater credentialsUpdater;

    /**
     * Creates the proxy.
     *
     * @param credentialsStore loads/stores Keepass {@linkplain Credentials} used for accessing Keepass.
     *
     * @throws IOException if an error occurs loading Keepass credentials from the store.
     */
    public KeepassProxy(KeepassCredentialsStore credentialsStore)
    throws IOException
    {
        this.credentialsStore = Objects.requireNonNull(credentialsStore);

        if (SystemUtils.IS_OS_WINDOWS)
            connection = new WindowsConnection();
        else
            connection = new LinuxMacConnection();

        credentialsUpdater = new CredentialsUpdater();
        connection.addPropertyChangeListener(credentialsUpdater);

        connection.setCredentials(Optional.ofNullable(credentialsStore.loadCredentials()));
    }

    private void handleConnectionCredentialsUpdate(Credentials credentials)
    {
        try
        {
            credentialsStore.saveCredentials(credentials);
        }
        catch (IOException e)
        {
            //TODO better exception handling
            throw new RuntimeException(e);
        }
    }

    @Override
    public void close()
    {
        connection.removePropertyChangeListener(credentialsUpdater);
        try
        {
            connection.close();
        }
        catch (Exception e)
        {
            throw new RuntimeException("Error closing Keepass connection: " + e, e);
        }
    }

    public void connect()
    throws IOException
    {
        connection.connect();
    }

    public boolean associate()
    {
        try
        {
            connection.associate();
            return true;
        }
        catch (IOException | KeepassProxyAccessException e)
        {
            //Like KeepassProxyAccess, associate() seems to always throw an exception due to some kind of workaround
            //So we just have to accept that this will always throw for the time being until the workaround is removed
            return false;
        }
    }

    public boolean connectionAvailable()
    {
        String publicKey = connection.getIdKeyPairPublicKey();
        if (publicKey == null || publicKey.isEmpty())
            return false;

        String associateId = connection.getAssociateId();
        if (associateId == null || associateId.isEmpty())
            return false;

        try
        {
            connection.testAssociate(connection.getAssociateId(), connection.getIdKeyPairPublicKey());
        }
        catch (IOException | KeepassProxyAccessException e)
        {
            return false;
        }

        return true;
    }

    public Map<String, String> exportConnection()
    {
        return Map.of("id", connection.getAssociateId(),
                      "key", connection.getIdKeyPairPublicKey());
    }

    public Map<String, Object> getLogins(String url, String submitUrl, boolean httpAuth, List<Map<String, String>> list)
    throws IOException, KeepassProxyAccessException
    {
        return connection.getLogins(url, submitUrl, httpAuth, list).toMap();
    }

    private class CredentialsUpdater implements PropertyChangeListener
    {
        @Override
        public void propertyChange(PropertyChangeEvent ev)
        {
            @SuppressWarnings("unchecked") Optional<Credentials> credentials = (Optional<Credentials>)ev.getNewValue();
            credentials.ifPresent(KeepassProxy.this::handleConnectionCredentialsUpdate);
        }
    }
}
