/**
 * Copyright 2024 SasanLabs
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
