package org.sasanlabs.fileupload.matcher.impl;

import java.util.Objects;
import java.util.function.Predicate;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.matcher.ContentMatcher;

/**
 * {@code ContainsExpectedValueMatcher} is used to match if the expected value is present in the
 * {@code HttpMessage} response body or not.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class ContainsExpectedValueMatcher implements ContentMatcher {

    private static final Predicate<HttpMessage> DEFAULT_PRECONDITION = (httpMessage) -> true;

    private Predicate<HttpMessage> precondition;
    private String expectedValue;

    public ContainsExpectedValueMatcher(String expectedValue) {
        this.precondition = DEFAULT_PRECONDITION;
        this.expectedValue = expectedValue;
    }

    public ContainsExpectedValueMatcher(Predicate<HttpMessage> precondition, String expectedValue) {
        Objects.requireNonNull(precondition, "Precondition cannot be null");
        this.precondition = precondition;
        this.expectedValue = expectedValue;
    }

    @Override
    public boolean match(HttpMessage msg) {
        if (!this.precondition.test(msg)) {
            return false;
        }
        // Assumption is toString is handled correctly by Owasp ZAP.
        return msg.getResponseBody().toString().contains(this.expectedValue);
    }
}
