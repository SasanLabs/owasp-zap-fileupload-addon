/**
 * Copyright 2021 SasanLabs
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
package org.sasanlabs.fileupload.attacks.apache.htaccess;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.FileUploadUtils;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.model.FileInformationProvider;
import org.sasanlabs.fileupload.attacks.model.SimpleFileInformationProvider;
import org.sasanlabs.fileupload.attacks.model.VulnerabilityType;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.function.ConsumerWithException;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.ContainsExpectedValueMatcher;

/**
 * Important documents or links to learn about .htaccess file:
 *
 * <ol>
 *   <li>https://serverfault.com/questions/780459/load-time-impact-of-htaccess
 *   <li>https://cwiki.apache.org/confluence/display/HTTPD/Htaccess
 *   <li>https://www.nginx.com/resources/wiki/start/topics/examples/likeapache-htaccess/
 *   <li>https://www.danielmorell.com/guides/htaccess-seo/basics/dont-use-htaccess-unless-you-must
 * </ol>
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class HTAccessFileUpload extends AttackVector {

    private static final String FILE_NAME = ".htaccess";
    private static final String NULL_BYTE_APPENDED_FILE_NAME =
            FILE_NAME + FileUploadUtils.NULL_BYTE_CHARACTER;
    private static final String HEX_NULL_BYTE_APPENDED_FILE_NAME = FILE_NAME + "%00";
    private static final List<FileInformationProvider> FILE_PARAMETERS =
            Arrays.asList(
                    originalFileName -> FILE_NAME,
                    new SimpleFileInformationProvider(fn -> FILE_NAME, ct -> "text/plain"),
                    originalFileName ->
                            NULL_BYTE_APPENDED_FILE_NAME
                                    + FileUploadUtils.prefixExtensionWithPeriodCharacter(
                                            FileUploadUtils.getExtension(originalFileName)),
                    new SimpleFileInformationProvider(
                            originalFileName ->
                                    NULL_BYTE_APPENDED_FILE_NAME
                                            + FileUploadUtils.prefixExtensionWithPeriodCharacter(
                                                    FileUploadUtils.getExtension(originalFileName)),
                            ct -> "text/html"),
                    originalFileName ->
                            HEX_NULL_BYTE_APPENDED_FILE_NAME
                                    + FileUploadUtils.prefixExtensionWithPeriodCharacter(
                                            FileUploadUtils.getExtension(originalFileName)),
                    new SimpleFileInformationProvider(
                            originalFileName ->
                                    HEX_NULL_BYTE_APPENDED_FILE_NAME
                                            + FileUploadUtils.prefixExtensionWithPeriodCharacter(
                                                    FileUploadUtils.getExtension(originalFileName)),
                            ct -> "text/plain"));
    private static final String EXPECTED_CONTENT = "Index of /";
    private static final ContentMatcher CONTENT_MATCHER =
            new ContainsExpectedValueMatcher(EXPECTED_CONTENT);
    private static final String HTACCESS_FILE_CONTENT = "Options +Indexes";

    @Override
    protected URI getUploadedFileURI(
            HttpMessage httpMsg,
            String fileName,
            ConsumerWithException<HttpMessage, IOException> sendAndRecieveHttpMsg)
            throws FileUploadException {
        URI uri = super.getUploadedFileURI(httpMsg, fileName, sendAndRecieveHttpMsg);
        try {
            if (uri != null && uri.getPath().lastIndexOf(FileUploadUtils.SLASH) != -1) {

                uri.setPath(
                        uri.getPath()
                                .substring(
                                        0, uri.getPath().lastIndexOf(FileUploadUtils.SLASH) + 1));
            }
        } catch (URIException e) {
            throw new FileUploadException("Unable to set the URI fragment", e);
        }
        return uri;
    }

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        return this.genericAttackExecutor(
                fileUploadAttackExecutor,
                HTACCESS_FILE_CONTENT,
                FILE_PARAMETERS,
                CONTENT_MATCHER,
                VulnerabilityType.HTACCESS_FILE);
    }
}
