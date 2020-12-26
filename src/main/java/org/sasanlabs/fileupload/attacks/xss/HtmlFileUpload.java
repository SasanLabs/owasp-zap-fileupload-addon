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
package org.sasanlabs.fileupload.attacks.xss;

import static org.sasanlabs.fileupload.Constants.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.Constants;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.beans.FileExtensionOperation;
import org.sasanlabs.fileupload.attacks.beans.FileParameter;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.MD5HashResponseMatcher;

/**
 * {@code HtmlFileUpload} attack vector will upload {@code html}, {@code htm}, {@code xhtml} etc
 * schemes in order to evaluate whether the application is vulnerable to {@code XSS} vulnerability.
 * <br>
 * General logic is if Application is allowing to upload {@code html} file and while downloading the
 * same file it is shown {@code inline} by the browser which is controlled by {@code
 * Content-Disposition} header then it is vulnerable to Stored XSS.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class HtmlFileUpload implements AttackVector {

    private static final String XSS_UPLOADED_FILE_BASE_NAME = "HtmlFileUpload_";
    private static final String XSS_PAYLOAD_HTML_FILE =
            "<html><head></head><body>Testing XSS</body></html>";

    private static final ContentMatcher CONTENT_MATCHER =
            new MD5HashResponseMatcher(
                    httpMsg -> isContentDispositionInline(httpMsg), XSS_PAYLOAD_HTML_FILE);

    private static boolean isContentDispositionInline(HttpMessage preflightMsg) {
        String headerValue = preflightMsg.getResponseHeader().getHeader("Content-Disposition");
        if (headerValue == null
                || headerValue.trim().equals(Constants.EMPTY_STRING)
                || headerValue.equals("inline")) {
            return true;
        }
        return false;
    }

    // Extended list for breaking black-listing strategy.
    private static final List<FileParameter> FILE_PARAMETERS_EXTENDED =
            Arrays.asList(
                    new FileParameter("Htm", Constants.EMPTY_STRING),
                    new FileParameter("hTM", Constants.EMPTY_STRING),
                    new FileParameter("HTM", Constants.EMPTY_STRING),
                    new FileParameter("Html", Constants.EMPTY_STRING),
                    new FileParameter("HtMl", Constants.EMPTY_STRING),
                    new FileParameter("HTMl", Constants.EMPTY_STRING),
                    new FileParameter("HTML", Constants.EMPTY_STRING),
                    new FileParameter("Xhtml", Constants.EMPTY_STRING),
                    new FileParameter("xHTml", Constants.EMPTY_STRING),
                    new FileParameter("xhTML", Constants.EMPTY_STRING),
                    new FileParameter("xHTML", Constants.EMPTY_STRING),
                    new FileParameter("XHTML", Constants.EMPTY_STRING),
                    new FileParameter("Htm", "text/html"),
                    new FileParameter("hTM", "text/html"),
                    new FileParameter("HTM", "text/html"),
                    new FileParameter("Html", "text/html"),
                    new FileParameter("HtMl", "text/html"),
                    new FileParameter("HTMl", "text/html"),
                    new FileParameter("HTML", "text/html"),
                    new FileParameter("Xhtml", "text/html"),
                    new FileParameter("xHTml", "text/html"),
                    new FileParameter("xhTML", "text/html"),
                    new FileParameter("xHTML", "text/html"),
                    new FileParameter("XHTML", "text/html"),
                    new FileParameter("Htm", "text/plain"),
                    new FileParameter("hTM", "text/plain"),
                    new FileParameter("HTM", "text/plain"),
                    new FileParameter("Html", "text/plain"),
                    new FileParameter("HtMl", "text/plain"),
                    new FileParameter("HTMl", "text/plain"),
                    new FileParameter("HTML", "text/plain"),
                    new FileParameter("Xhtml", "text/plain"),
                    new FileParameter("xHTml", "text/plain"),
                    new FileParameter("xhTML", "text/plain"),
                    new FileParameter("xHTML", "text/plain"),
                    new FileParameter("XHTML", "text/plain"),
                    new FileParameter(
                            "Htm", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "hTM", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTM", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Html", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HtMl", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTMl", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTML", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Xhtml", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xHTml", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xhTML", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xHTML", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "XHTML", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Htm", "text/plain", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "hTM", "text/plain", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTM", "text/plain", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Html", "text/plain", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HtMl", "text/plain", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTMl", "text/plain", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTML", "text/plain", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Xhtml",
                            "text/plain",
                            FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xHTml",
                            "text/plain",
                            FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xhTML",
                            "text/plain",
                            FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xHTML",
                            "text/plain",
                            FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "XHTML",
                            "text/plain",
                            FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Htm" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "hTM" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTM" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Html" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HtMl" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTMl" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTML" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Xhtml" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xHTml" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xhTML" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xHTML" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "XHTML" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Htm" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "hTM" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTM" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Html" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HtMl" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTMl" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTML" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Xhtml" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xHTml" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xhTML" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xHTML" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "XHTML" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION));

    private static final List<FileParameter> FILE_PARAMETERS_DEFAULT =
            Arrays.asList(
                    new FileParameter("htm", Constants.EMPTY_STRING),
                    new FileParameter("html", Constants.EMPTY_STRING),
                    new FileParameter("xhtml", Constants.EMPTY_STRING),
                    new FileParameter("htm", "text/html"),
                    new FileParameter("html", "text/html"),
                    new FileParameter("xhtml", "text/html"),
                    new FileParameter("htm", "text/plain"),
                    new FileParameter("html", "text/plain"),
                    new FileParameter("xhtml", "text/plain"),
                    new FileParameter(
                            "htm", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "html", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xhtml", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "htm" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "html" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xhtml" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "htm" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "html" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xhtml" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION));

    /**
     * @throws FileUploadException
     * @throws IOException
     */
    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        boolean result = false;
        try {
            result =
                    this.genericAttackExecutor(
                            fileUploadAttackExecutor,
                            CONTENT_MATCHER,
                            XSS_PAYLOAD_HTML_FILE,
                            XSS_UPLOADED_FILE_BASE_NAME,
                            FILE_PARAMETERS_DEFAULT);
            if (result) {
                fileUploadAttackExecutor
                        .getFileUploadScanRule()
                        .raiseAlert(
                                1,
                                1,
                                "",
                                "",
                                "",
                                "",
                                "",
                                "",
                                "",
                                fileUploadAttackExecutor.getOriginalHttpMessage());
            } else {
                if (fileUploadAttackExecutor
                        .getFileUploadScanRule()
                        .getAttackStrength()
                        .equals(AttackStrength.INSANE)) {
                    result =
                            this.genericAttackExecutor(
                                    fileUploadAttackExecutor,
                                    CONTENT_MATCHER,
                                    XSS_PAYLOAD_HTML_FILE,
                                    XSS_UPLOADED_FILE_BASE_NAME,
                                    FILE_PARAMETERS_EXTENDED);
                    if (result) {
                        fileUploadAttackExecutor
                                .getFileUploadScanRule()
                                .raiseAlert(
                                        1,
                                        1,
                                        "",
                                        "",
                                        "",
                                        "",
                                        "",
                                        "",
                                        "",
                                        fileUploadAttackExecutor.getOriginalHttpMessage());
                    }
                }
            }
        } catch (IOException e) {
            throw new FileUploadException(e);
        }
        return result;
    }
}
