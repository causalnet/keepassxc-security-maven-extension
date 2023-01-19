package au.net.causal.maven.plugins.keepassxc;

import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

/**
 * The fail mode determines what the decryptor should do when a password cannot be read from KeepassXC for some reason.
 */
public enum FailMode
{
    /**
     * Resolve to an empty string as the password when the real password cannot be read from KeepassXC.
     */
    EMPTY_PASSWORD
    {
        @Override
        public String handleKeepassFailure(SecDispatcherException ex)
        throws SecDispatcherException
        {
            return "";
        }
    },
    /**
     * Throw an exception when the password cannot be read from KeepassXC.  This has a side effect of not translating the
     * settings.xml server entry at all, which means the {@code {[type=keepassxc]https://server}} string could be used for authentication
     * to servers when not able to read a password from KeepassXC.
     */
    EXCEPTION
    {
        @Override
        public String handleKeepassFailure(SecDispatcherException ex)
        throws SecDispatcherException
        {
            throw ex;
        }
    };

    /**
     * Handle a failure reading a password from KeepassXC.
     *
     * @param ex the exception.
     *
     * @return the replacement password to use when this error occurs.
     *
     * @throws SecDispatcherException if this fail mode throws an exception when KeepassXC failures occur.
     */
    public abstract String handleKeepassFailure(SecDispatcherException ex)
    throws SecDispatcherException;
}
