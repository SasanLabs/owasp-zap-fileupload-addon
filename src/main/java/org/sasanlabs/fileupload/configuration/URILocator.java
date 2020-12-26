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
package org.sasanlabs.fileupload.configuration;

import java.io.IOException;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.attacks.ConsumerWithException;
import org.sasanlabs.fileupload.attacks.FileUploadException;

/**
 * {@code URILocator} class is used to find the URL either by parsing the {@code HttpMessage} or
 * reading the configuration mentioned in the options tab.
 *
 * <p>This class also handles the "regex based configuration" e.g "url/{$fileName}"
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public interface URILocator {
    URI get(
            HttpMessage msg,
            String fileName,
            ConsumerWithException<HttpMessage, IOException> sendAndRecieve)
            throws FileUploadException, IOException;
}
