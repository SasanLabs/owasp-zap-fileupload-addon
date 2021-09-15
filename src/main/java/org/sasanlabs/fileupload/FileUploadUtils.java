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
package org.sasanlabs.fileupload;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.attacks.model.FileExtensionOperation;
import org.sasanlabs.fileupload.attacks.model.FileInformationProvider;
import org.sasanlabs.fileupload.attacks.model.FileInformationProviderBuilder;

/**
 * Contains the String constants or other utility functions used by the Addon.
 *
 * @author preetkaran20@gmail.com KSASAN
 * @since 1.0.0
 */
public interface FileUploadUtils {
    String EMPTY_STRING = "";
    String PERIOD = ".";
    String SLASH = "/";
    String NULL_BYTE_CHARACTER = String.valueOf((char) 0);
    String HTTP_SCHEME = "http://";
    String HTTP_SECURED_SCHEME = "https://";
    String HTML_MIME_TYPE = "text/html";
    String XHTML_MIME_TYPE = "application/xhtml+xml";
    String SVG_MIME_TYPE = "image/svg+xml";
    String GET_HTTP_METHOD = "GET";
    String JSP_FILE_EXTENSION = "jsp";
    String JSPX_FILE_EXTENSION = "jspx";

    /**
     * Appends the Period Character to the provided String.
     *
     * @param extension, extension of the file
     * @return appends {@link #PERIOD} to the provided extension if not {@code null} or empty else
     *     returns same provided extension.
     */
    static String prefixExtensionWithPeriodCharacter(String extension) {
        if (StringUtils.isBlank(extension) || extension.startsWith(FileUploadUtils.PERIOD)) {
            return extension;
        } else {
            return FileUploadUtils.PERIOD + extension;
        }
    }

    /**
     * returns the extension of the provided fileName.
     *
     * @param fileName, name of the file
     * @return extension of the provided fileName if not null else throws {@code
     *     NullPointerException}
     */
    static String getExtension(String fileName) {
        Objects.requireNonNull(fileName, "FileName cannot be null");
        int firstIndexOfPeriodCharacter = fileName.indexOf(FileUploadUtils.PERIOD);
        if (firstIndexOfPeriodCharacter >= 0) {
            return fileName.substring(firstIndexOfPeriodCharacter + 1);
        }
        return null;
    }

    /**
     * Checks whether {@code Content-Disposition} header is inline and if so returns {@code True}
     * else {@code False}
     *
     * <p>This utility is useful to find if XSS is possible or not because if {@code
     * Content-Disposition} header is inline then only XSS is possible.
     *
     * @param httpMsg, HttpMessage representing request and response
     * @return {@code True} if {@code Content-Disposition} header is inline
     */
    static boolean isContentDispositionInline(HttpMessage httpMsg) {
        String headerValue = httpMsg.getResponseHeader().getHeader("Content-Disposition");
        if (headerValue == null
                || headerValue.trim().equals(FileUploadUtils.EMPTY_STRING)
                || headerValue.equals("inline")) {
            return true;
        }
        return false;
    }

    /**
     * Utility to check if the {@code HttpHeader#CONTENT_TYPE} header is present in the {@code
     * HttpMessage}
     *
     * @param httpMsg, HttpMessage representing request and response
     * @return {@code True} if {@code HttpHeader#CONTENT_TYPE} header is present in httpMsg else
     *     {@code False}
     */
    static boolean isContentTypeHeaderPresent(HttpMessage httpMsg) {
        String headerValue = httpMsg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
        return StringUtils.isNotBlank(headerValue);
    }

    /**
     * Documents with active scripts can be executed by browser based on the {@code
     * HttpHeader#CONTENT_TYPE} header.
     *
     * <p>References {@link
     * https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#RULE_.233.1_-_HTML_escape_JSON_values_in_an_HTML_context_and_read_the_data_with_JSON.parse:#:~:text=Good%20HTTP%20response:}
     * and {@link
     * https://security.stackexchange.com/questions/169427/impact-of-the-response-content-type-on-the-exploitability-of-xss}
     *
     * @param httpMsg, HttpMessage representing request and response
     * @return {@code True} if content type is one of {@code FileUploadUtils#HTML_MIME_TYPE} or
     *     {@code FileUploadUtils#XHTML_MIME_TYPE} or {@code FileUploadUtils#SVG_MIME_TYPE}
     */
    static boolean isContentTypeCausesJavascriptExecution(HttpMessage httpMsg) {
        String headerValue = httpMsg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
        return StringUtils.isNotBlank(headerValue)
                && (headerValue.equalsIgnoreCase(HTML_MIME_TYPE)
                        || headerValue.equalsIgnoreCase(XHTML_MIME_TYPE)
                        || headerValue.equalsIgnoreCase(SVG_MIME_TYPE));
    }

    /**
     * Provides extended list of FileInformationProvider for JSP.
     *
     * @param baseFileName, base file name of uploaded jsp file.
     * @return list of FileInformationProvider for JSP
     */
    static List<FileInformationProvider> getFileInformationProvidersExtendedJsp(
            String baseFileName) {
        return Arrays.asList(
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension("Jsp")
                        .withFileExtensionOperation(FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension("JSP")
                        .withFileExtensionOperation(FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension("Jsp")
                        .withContentType("application/x-jsp")
                        .withFileExtensionOperation(FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension("JSP")
                        .withContentType("application/x-jsp")
                        .withFileExtensionOperation(FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                        .build());
    }

    /**
     * Provides default list of FileInformationProvider for JSP.
     *
     * @param baseFileName, base file name of uploaded jsp file.
     * @param extension, extension of the uploaded jsp file.
     * @return list of FileInformationProvider for JSP
     */
    static List<FileInformationProvider> getFileInformationProvidersDefaultJsp(
            String baseFileName, String extension) {
        return Arrays.asList(
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(extension)
                        .withFileExtensionOperation(FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(extension)
                        .withContentType("application/x-jsp")
                        .withFileExtensionOperation(FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(extension)
                        .withFileExtensionOperation(
                                FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(extension)
                        .withContentType("application/x-jsp")
                        .withFileExtensionOperation(
                                FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(extension + NULL_BYTE_CHARACTER)
                        .withFileExtensionOperation(
                                FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(extension + NULL_BYTE_CHARACTER)
                        .withContentType("application/x-jsp")
                        .withFileExtensionOperation(
                                FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(extension + "%00")
                        .withFileExtensionOperation(
                                FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(extension + "%00")
                        .withContentType("application/x-jsp")
                        .withFileExtensionOperation(
                                FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                        .build());
    }

    /**
     * Provides the list of FileInformationProviders for PHP by baseFileName and php extension
     *
     * @param baseFileName, base file name of uploaded php file.
     * @param phpExtension, extension of the uploaded php file.
     * @return list of FileInformationProvider for PHP
     */
    static List<FileInformationProvider> getFileInformationProvidersByExtensionPHP(
            String baseFileName, String phpExtension) {
        return Arrays.asList(
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(phpExtension)
                        .withFileExtensionOperation(FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(phpExtension)
                        .withContentType("application/x-httpd-php")
                        .withFileExtensionOperation(FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(phpExtension)
                        .withFileExtensionOperation(
                                FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                        .build(),
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(phpExtension)
                        .withContentType("application/x-httpd-php")
                        .withFileExtensionOperation(
                                FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                        .build(),

                /**
                 * If .htaccess has following configuration <code>
                 * AddHandler application/x-httpd-php .php</code> and if the file ends with the
                 * original extension but has .php in the name then also php will be executed For
                 * more information: https://www.acunetix.com/websitesecurity/upload-forms-threat/
                 * and
                 * https://github.com/SasanLabs/VulnerableApp-php/blob/main/src/FileUploadVulnerability/FileUpload.php#L276
                 */
                new FileInformationProviderBuilder(baseFileName)
                        .withExtension(phpExtension)
                        .withFileExtensionOperation(
                                FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                        .build());
    }

    /**
     * Provides the list of FileInformationProvider for PHP provided the baseFileName and list of
     * php extension variants
     *
     * @param baseFileName, base file name of uploaded php file.
     * @param phpExtension, extension of the uploaded php file.
     * @return list of FileInformationProvider for PHP
     */
    static List<FileInformationProvider> getFileInformationProvidersPHP(
            String baseFileName, List<String> extensions) {
        List<FileInformationProvider> fileInformationProviders = new ArrayList<>();
        for (String extension : extensions) {
            fileInformationProviders.addAll(
                    getFileInformationProvidersByExtensionPHP(baseFileName, extension));
        }
        return fileInformationProviders;
    }
}
