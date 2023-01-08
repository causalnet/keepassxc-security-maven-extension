package au.net.causal.maven.plugins.keepassxc;

import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

public enum FailMode
{
    EMPTY_PASSWORD
    {
        @Override
        public String handleKeepassFailure(SecDispatcherException ex)
        throws SecDispatcherException
        {
            return "";
        }
    },
    EXCEPTION
    {
        @Override
        public String handleKeepassFailure(SecDispatcherException ex)
        throws SecDispatcherException
        {
            throw ex;
        }
    };

    public abstract String handleKeepassFailure(SecDispatcherException ex)
    throws SecDispatcherException;
}
