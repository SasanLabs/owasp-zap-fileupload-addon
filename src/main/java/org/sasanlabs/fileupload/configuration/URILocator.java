package org.sasanlabs.fileupload.configuration;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.network.HttpMessage;

/**
 * {@code URILocator} class is used to find the URL either by parsing the {@code HttpMessage} or
 * reading the configuration mentioned in the options tab.
 *
 * <p>This class also handles the "regex based configuration" e.g "url/$fileName"
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public interface URILocator {
    URI get(HttpMessage msg) throws URIException;
}
