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

    private static final String XSS_UPLOADED_FILE_BASE_NAME = "HtmlFileUpload_XSS_";
    private static final String XSS_PAYLOAD_HTML_FILE =
            "<html><head></head><body>Testing XSS</body></html>";

    static final ContentMatcher CONTENT_MATCHER =
            new MD5HashResponseMatcher(
                    httpMsg -> Constants.isContentDispositionInline(httpMsg),
                    XSS_PAYLOAD_HTML_FILE);

    // Extended list for breaking black-listing strategy.
    private static final List<FileParameter> FILE_PARAMETERS_EXTENDED =
            Arrays.asList(
                    new FileParameter("Htm"),
                    new FileParameter("hTM"),
                    new FileParameter("HTM"),
                    new FileParameter("Html"),
                    new FileParameter("HtMl"),
                    new FileParameter("HTMl"),
                    new FileParameter("HTML"),
                    new FileParameter("Xhtml"),
                    new FileParameter("xHTml"),
                    new FileParameter("xhTML"),
                    new FileParameter("xHTML"),
                    new FileParameter("XHTML"),
                    new FileParameter("dHtml"),
                    new FileParameter("sHtml"),
                    new FileParameter("dHTml"),
                    new FileParameter("sHTml"),
                    new FileParameter("dHTML"),
                    new FileParameter("sHTML"),
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
                    new FileParameter("dHtml", "text/html"),
                    new FileParameter("sHtml", "text/html"),
                    new FileParameter("dHTml", "text/html"),
                    new FileParameter("sHTml", "text/html"),
                    new FileParameter("dHTML", "text/html"),
                    new FileParameter("sHTML", "text/html"),
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
                    new FileParameter("dHtml", "text/plain"),
                    new FileParameter("sHtml", "text/plain"),
                    new FileParameter("dHTml", "text/plain"),
                    new FileParameter("sHTml", "text/plain"),
                    new FileParameter("dHTML", "text/plain"),
                    new FileParameter("sHTML", "text/plain"),
                    new FileParameter(
                            "Htm", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "HTML", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "Xhtml", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "XHTML", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter("Htm", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter("HTML", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter("Xhtml", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter("XHTML", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION));

    private static final List<FileParameter> FILE_PARAMETERS_DEFAULT =
            Arrays.asList(
                    new FileParameter("htm"),
                    new FileParameter("html"),
                    new FileParameter("xhtml"),
                    /**
                     * Server Parsed Html for server side includes
                     * https://stackoverflow.com/questions/519619/what-is-the-purpose-and-uniqueness-shtml
                     */
                    new FileParameter("shtml"),
                    new FileParameter("dhtml"),
                    new FileParameter("htm", "text/html"),
                    new FileParameter("html", "text/html"),
                    new FileParameter("xhtml", "text/html"),
                    new FileParameter("shtml", "text/html"),
                    new FileParameter("dhtml", "text/html"),
                    new FileParameter("htm", "text/plain"),
                    new FileParameter("html", "text/plain"),
                    new FileParameter("xhtml", "text/plain"),
                    new FileParameter("shtml", "text/plain"),
                    new FileParameter("dhtml", "text/plain"),
                    new FileParameter(
                            "htm", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "html", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "xhtml", "text/html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter("htm", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter("html", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter("xhtml", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "htm" + NULL_BYTE_CHARACTER,
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "htm" + NULL_BYTE_CHARACTER,
                            "text/html",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "htm" + NULL_BYTE_CHARACTER,
                            "text/plain",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    /**
                     * *
                     *
                     * <p>As per owasp file upload use both NULL BYtes with URL encoded and decoded
                     *
                     * <p>we need to do the same in our code. Important.
                     *
                     * <p>ADD This
                     */
                    new FileParameter(
                            "htm" + NULL_BYTE_CHARACTER,
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)

                    /**
                     * My thought is that if server is vulnerable to Null Byte then it is sure that
                     * "htm" only will work and there is no need to verify other extensions *
                     */
                    /*
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
                                                FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                    */
                    );

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
