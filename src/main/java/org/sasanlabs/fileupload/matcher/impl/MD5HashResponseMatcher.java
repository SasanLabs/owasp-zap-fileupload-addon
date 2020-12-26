/**
 * Copyright 2020 SasanLabs
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sasanlabs.fileupload.matcher.impl;

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
            // Assumption is ZAP will check the charset and returns the response body as "String" as
            // per the charset.
            byte[] digest =
                    messageDigest.digest(
                            msg.getResponseBody().toString().getBytes(StandardCharsets.UTF_8));
            return Arrays.equals(
                    digest, messageDigest.digest(expectedValue.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.debug("Error occurred while comparing MD5 Hash ", ex);
        }
        return false;
    }
}
