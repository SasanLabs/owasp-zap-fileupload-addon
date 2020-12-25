package org.sasanlabs.fileupload.configuration;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.network.HttpMessage;

public class URILocatorImpl implements URILocator {

    @Override
    public URI get(HttpMessage msg) throws URIException {
        byte[] responseBody = msg.getResponseBody().getBytes();

        // Say static configuration
        return new URI("http://localhost:9090/contentDispositionUpload/karan.html");
    }
}
