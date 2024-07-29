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
package org.sasanlabs.fileupload.locator;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringSubstitutor;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.FileUploadUtils;
import org.sasanlabs.fileupload.configuration.FileUploadConfiguration;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.function.ConsumerWithException;

/**
 * {@code URILocatorImpl} class is used to find the URL either by 1. returning the static url
 * mentioned by user in Options tab. This also handles the dynamic file names e.g. <code>
 * http://<baseurl>/${fileName}</code> 2. parsing the original {@code HttpMessage} and using dynamic
 * configuration to find the complete URI. 3. Invokes the preflight request as mentioned by dynamic
 * configuration and then parsing the preflighted {@code HttpMessage}
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class URILocatorImpl implements URILocator {

    protected static final Logger LOGGER = Logger.getLogger(URILocatorImpl.class);

    private URI getCompleteURI(String uriRegex, String fileName, HttpMessage msg)
            throws URIException, FileUploadException {
        if (fileName.contains(FileUploadUtils.NULL_BYTE_CHARACTER)) {
            fileName = fileName.substring(0, fileName.indexOf(FileUploadUtils.NULL_BYTE_CHARACTER));
        }
        Map<String, String> replacerKeyValuePair = Collections.singletonMap("filename", fileName);
        StringSubstitutor stringSubstitutor = new StringSubstitutor(replacerKeyValuePair);
        String uriFragment = stringSubstitutor.replace(uriRegex);
        if (uriFragment.startsWith(FileUploadUtils.HTTP_SCHEME)
                || uriRegex.startsWith(FileUploadUtils.HTTP_SECURED_SCHEME)) {
            return new URI(uriFragment, true);
        } else {
            if (!uriFragment.startsWith(FileUploadUtils.SLASH)) {
                uriFragment = FileUploadUtils.SLASH + uriFragment;
            }
            String authority = msg.getRequestHeader().getURI().getAuthority();
            String scheme = msg.getRequestHeader().getURI().getScheme();
            return new URI(scheme, authority, uriFragment, "");
        }
    }

    private URI parseResponseAndGetCompleteURI(
            HttpMessage msg, String fileName, HttpMessage originalMsg)
            throws FileUploadException, URIException {
        int startIndex =
                msg.getResponseBody()
                        .toString()
                        .indexOf(
                                FileUploadConfiguration.getInstance()
                                        .getParseResponseStartIdentifier());
        int endIndex =
                msg.getResponseBody()
                        .toString()
                        .indexOf(
                                FileUploadConfiguration.getInstance()
                                        .getParseResponseEndIdentifier());
        if (startIndex < 0 || endIndex < 0 || startIndex > endIndex) {
            throw new FileUploadException(
                    "StartIndex or EndIndex configuration is either not present in the response or invalid. Start index:"
                            + startIndex
                            + " End index:"
                            + endIndex);
        }
        String uriRegex =
                msg.getResponseBody()
                        .toString()
                        .substring(
                                startIndex
                                        + FileUploadConfiguration.getInstance()
                                                .getParseResponseStartIdentifier()
                                                .length(),
                                endIndex);
        return this.getCompleteURI(uriRegex, fileName, originalMsg);
    }

    @Override
    public URI get(
            HttpMessage msg,
            String fileName,
            ConsumerWithException<HttpMessage, IOException> sendAndRecieve)
            throws FileUploadException {
        try {
            if (StringUtils.isNotBlank(
                    FileUploadConfiguration.getInstance().getStaticLocationURIRegex())) {
                return this.getCompleteURI(
                        FileUploadConfiguration.getInstance().getStaticLocationURIRegex(),
                        fileName,
                        msg);
            } else if (StringUtils.isNotBlank(
                    FileUploadConfiguration.getInstance().getDynamicLocationURIRegex())) {
                // Do an HttpCall and then find URI of uploaded content in Response.
                HttpMessage preflightRequest = msg.cloneRequest();
                preflightRequest
                        .getRequestHeader()
                        .setURI(
                                this.getCompleteURI(
                                        FileUploadConfiguration.getInstance()
                                                .getDynamicLocationURIRegex(),
                                        fileName,
                                        msg));
                sendAndRecieve.accept(preflightRequest);
                return this.parseResponseAndGetCompleteURI(preflightRequest, fileName, msg);
            } else {
                if (StringUtils.isNotBlank(
                                FileUploadConfiguration.getInstance()
                                        .getParseResponseStartIdentifier())
                        && StringUtils.isNotBlank(
                                FileUploadConfiguration.getInstance()
                                        .getParseResponseEndIdentifier())) {
                    try {
                        return this.parseResponseAndGetCompleteURI(msg, fileName, msg);
                    } catch (FileUploadException e) {
                        // Eating exception because upload request might not have the uri
                        LOGGER.debug(e);
                    }
                }
            }
        } catch (IOException ex) {
            throw new FileUploadException(ex);
        }
        return null;
    }
}
