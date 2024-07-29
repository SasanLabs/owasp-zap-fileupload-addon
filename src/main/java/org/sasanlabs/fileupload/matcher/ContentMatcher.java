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
package org.sasanlabs.fileupload.matcher;

import org.parosproxy.paros.network.HttpMessage;

/**
 * {@code ContentMatcher} class is used to match the contents of provided {@code HttpMessage} with
 * the expected values
 *
 * @author preetkaran20@gmail.com KSASAN
 */
@FunctionalInterface
public interface ContentMatcher {

    /**
     * @param msg, {@code HttpMessage} for comparing with the expected values
     * @return {@code True} if {@code HttpMessage} matches with the expected values else {@code
     *     False}
     */
    boolean match(HttpMessage msg);
}
