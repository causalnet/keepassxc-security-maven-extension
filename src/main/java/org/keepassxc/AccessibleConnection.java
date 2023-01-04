package org.keepassxc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;

/**
 * Hack to make some package-protected stuff accessible to other packages.
 */

//There's some shadowing and other shenanigans going on here, but the point is so the connection subclasses can be copy+pasted into another package
//and they work with minimal or even zero code changes
public abstract class AccessibleConnection extends Connection
{
    private static final Logger LOG = LoggerFactory.getLogger(AccessibleConnection.class);

    //Just to make super's one accessible
    protected final ExecutorService executorService = super.executorService;

    //Intentional shadow from superclass - it's only ever used in subs anyway so the super's one can stay null
    protected MessagePublisher messagePublisher;

    protected void lauchMessagePublisher()
    {
        messagePublisher = new MessagePublisher();
        LOG.debug("MessagePublisher started");
        executorService.execute(messagePublisher);
    }

    protected class MessagePublisher extends Connection.MessagePublisher
    {
    }
}
