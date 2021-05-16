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

import java.util.Objects;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Contains the String constants or other utility constants used by the File Upload Addon.
 *
 * @author preetkaran20@gmail.com KSASAN
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

    /**
     * Appends the Period Character to the provided String.
     *
     * @param extension
     * @return
     */
    static String appendPeriodCharacter(String extension) {
        if (StringUtils.isBlank(extension)) {
            return extension;
        } else {
            if (extension.startsWith(FileUploadUtils.PERIOD)) {
                return extension;
            }
            return FileUploadUtils.PERIOD + extension;
        }
    }

    /**
     * returns the extension of the provided fileName.
     *
     * @param fileName
     * @return extension of the provided fileName
     * @throws Null Pointer Exception if fileName is null
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
     * @param preflightMsg
     * @return {@code True} if {@code Content-Disposition} header is inline
     */
    static boolean isContentDispositionInline(HttpMessage preflightMsg) {
        String headerValue = preflightMsg.getResponseHeader().getHeader("Content-Disposition");
        if (headerValue == null
                || headerValue.trim().equals(FileUploadUtils.EMPTY_STRING)
                || headerValue.equals("inline")) {
            return true;
        }
        return false;
    }

    static boolean isContentTypeHeaderPresent(HttpMessage preflightMsg) {
        String headerValue = preflightMsg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
        return StringUtils.isNotBlank(headerValue);
    }

    /**
     * References {@link
     * https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#RULE_.233.1_-_HTML_escape_JSON_values_in_an_HTML_context_and_read_the_data_with_JSON.parse:#:~:text=Good%20HTTP%20response:}
     * and {@link
     * https://security.stackexchange.com/questions/169427/impact-of-the-response-content-type-on-the-exploitability-of-xss}
     *
     * @param preflightMsg
     * @return {@code True} is content type is one of {@code FileUploadUtils#HTML_MIME_TYPE} or
     *     {@code FileUploadUtils#XHTML_MIME_TYPE} or {@code FileUploadUtils#SVG_MIME_TYPE}
     */
    static boolean isContentTypeCausesJavascriptExecution(HttpMessage preflightMsg) {
        String headerValue = preflightMsg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
        return StringUtils.isNotBlank(headerValue)
                && (headerValue.equalsIgnoreCase(HTML_MIME_TYPE)
                        || headerValue.equalsIgnoreCase(XHTML_MIME_TYPE)
                        || headerValue.equalsIgnoreCase(SVG_MIME_TYPE));
    }
}
