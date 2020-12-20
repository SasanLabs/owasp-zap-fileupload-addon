package org.sasanlabs.fileupload.matcher;

import org.parosproxy.paros.network.HttpMessage;

/**
 * {@code ContentMatcher} class is used to compare the contents of
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public interface ContentMatcher {

    boolean match(HttpMessage msg);
}
