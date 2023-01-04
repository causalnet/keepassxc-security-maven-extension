package au.net.causal.maven.plugins.keepassxc;

import org.purejava.Credentials;

import java.io.IOException;

/**
 * Loads and saves Keepass store credentials, used for accessing Keepass.
 */
public interface KeepassCredentialsStore
{
    /**
     * Saves credentials to the perisent store.
     *
     * @param credentials credentials to save.
     *
     * @throws IOException if an error occurs.
     */
    public void saveCredentials(Credentials credentials)
    throws IOException;

    /**
     * Loads pre-existing credentials if they exist.
     *
     * @return loaded credentials, or null if there are none.
     *
     * @throws IOException if an error occurs.
     */
    public Credentials loadCredentials()
    throws IOException;
}
