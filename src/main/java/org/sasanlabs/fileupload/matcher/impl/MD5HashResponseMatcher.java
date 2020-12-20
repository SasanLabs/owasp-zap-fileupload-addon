package org.sasanlabs.fileupload.matcher.impl;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Predicate;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.matcher.ContentMatcher;

/**
 * {@code MD5HashResponseMatcher} matches {@code MD5} hashes of both the contents
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class MD5HashResponseMatcher implements ContentMatcher {
    private static final Logger LOGGER = Logger.getLogger(MD5HashResponseMatcher.class);

    private static final Predicate<HttpMessage> DEFAULT_PRECONDITION = (httpMessage) -> true;

    private Predicate<HttpMessage> precondition;
    private String expectedValue;

    public MD5HashResponseMatcher(String expectedValue) {
        this.precondition = DEFAULT_PRECONDITION;
        this.expectedValue = expectedValue;
    }

    public MD5HashResponseMatcher(Predicate<HttpMessage> precondition, String expectedValue) {
        Objects.requireNonNull(precondition, "Precondition cannot be null");
        this.precondition = precondition;
        this.expectedValue = expectedValue;
    }

    @Override
    public boolean match(HttpMessage msg) {
        if (!this.precondition.test(msg)) {
            return false;
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            byte[] digest = messageDigest.digest(msg.getRequestBody().getBytes());
            String charSet = msg.getRequestHeader().getCharset();
            Charset responseCharSet =
                    charSet != null ? Charset.forName(charSet) : StandardCharsets.UTF_8;
            return Arrays.equals(
                    digest, messageDigest.digest(expectedValue.getBytes(responseCharSet)));
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.debug("Error occurred while comparing MD5 Hash ", ex);
        }
        return false;
    }
}
