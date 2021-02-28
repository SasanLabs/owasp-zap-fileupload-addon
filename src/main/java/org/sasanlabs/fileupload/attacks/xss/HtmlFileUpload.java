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
package org.sasanlabs.fileupload.attacks.xss;

import static org.sasanlabs.fileupload.FileUploadUtils.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.sasanlabs.fileupload.FileUploadUtils;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.beans.FileExtensionOperation;
import org.sasanlabs.fileupload.attacks.beans.FileParameter;
import org.sasanlabs.fileupload.attacks.beans.FileParameterBuilder;
import org.sasanlabs.fileupload.attacks.beans.VulnerabilityType;
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

    /**
     * Precondition: <br>
     * 1. ContentDisposition should be inline <br>
     * 2. ContentType should be {@link FileUploadUtils#HTML_MIME_TYPE} or {@link
     * FileUploadUtils#XHTML_MIME_TYPE} <br>
     * or blank Note: here we are not considering the invalid content type header values because
     * that should not be there.
     */
    static final ContentMatcher CONTENT_MATCHER =
            new MD5HashResponseMatcher(
                    httpMsg ->
                            FileUploadUtils.isContentDispositionInline(httpMsg)
                                    && (!FileUploadUtils.isContentTypeHeaderPresent(httpMsg)
                                            || FileUploadUtils
                                                    .isContentTypeCausesJavascriptExecution(
                                                            httpMsg)),
                    XSS_PAYLOAD_HTML_FILE);

    // Extended list for breaking black-listing strategy.
    private static final List<FileParameter> FILE_PARAMETERS_EXTENDED =
            Arrays.asList(
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Htm")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("hTM")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTM")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HtML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTMl")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Xhtml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xHTml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xhTML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xHTML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("XHTML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dHtml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("sHtml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dHTml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("sHTml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dHTML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("sHTML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Htm")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("hTM")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTM")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Html")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HtML")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTMl")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTML")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Xhtml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xHTml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xhTML")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xHTML")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("XHTML")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dHtml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("sHtml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dHTml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("sHTml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dHTML")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("sHTML")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Htm")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("hTM")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTM")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Html")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HtML")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTMl")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTML")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Xhtml")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xHTml")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xhTML")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xHTML")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("XHTML")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dHtml")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("sHtml")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dHTml")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("sHTml")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dHTML")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("sHTML")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Htm")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Xhtml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("XHTML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Htm")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Htm")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("HTML")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Xhtml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("XHTML")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Htm")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build());

    private static final List<FileParameter> FILE_PARAMETERS_DEFAULT =
            Arrays.asList(
                    /**
                     * No extension is required actually browser reads the content-type header of
                     * response from server and if that is not present then it tried to guess the
                     * file type based on the extension and in case content type and extensions are
                     * missing then browser finds it by reading the response called content
                     * sniffing. More information : <br>
                     * {@link https://en.wikipedia.org/wiki/Content_sniffing} <br>
                     * {@link
                     * https://stackoverflow.com/questions/2148443/does-file-extensions-matter-for-browsers}
                     */
                    /**
                     * Sometimes the logic is broken in a way that it fetches fileName after {@code
                     * .} character if dot is not present then it returns the entire fileName and
                     * then compares it with valid extension list.
                     *
                     * <p>e.g. php code {@code
                     * strtolower(end(explode('.',$_FILES['image']['name'])));}
                     */
                    new FileParameterBuilder().withFileNameAsOriginalExtension().build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withFileExtensionOperation(FileExtensionOperation.NO_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xhtml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    /**
                     * Server Parsed Html for server side includes
                     * https://stackoverflow.com/questions/519619/what-is-the-purpose-and-uniqueness-shtml
                     */
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dhtml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("shtml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    /**
                     * The way apache server considers the file extension is: it takes the right
                     * most valid extension type which in this case is html. so this can bypass the
                     * blacklist validation of extensions. For more information {@link
                     * https://www.acunetix.com/websitesecurity/upload-forms-threat/#:~:text=Double%20Extensions}
                     */
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("html.123")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("html")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xhtml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("shtml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dhtml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("html")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xhtml")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("shtml")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("dhtml")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    /**
                     * Say original extension is {@code .gif} then this will change it to {@code
                     * .gif.html} If validator only validates contains {@code .gif} extension then
                     * validator will be bypassed.
                     */
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("html")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xhtml")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xhtml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm" + NULL_BYTE_CHARACTER)
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm" + NULL_BYTE_CHARACTER)
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm" + NULL_BYTE_CHARACTER)
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm%00")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm%00")
                            .withContentType("text/html")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("htm%00")
                            .withContentType("text/plain")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build()
                    /**
                     * My thought is that if server is vulnerable to Null Byte then it is sure that
                     * "htm" only will work and there is no need to verify other extensions
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
                            FILE_PARAMETERS_DEFAULT,
                            VulnerabilityType.XSS_HTML_FILE);
            if (!result
                    && fileUploadAttackExecutor
                            .getFileUploadScanRule()
                            .getAttackStrength()
                            .equals(AttackStrength.INSANE)) {
                result =
                        this.genericAttackExecutor(
                                fileUploadAttackExecutor,
                                CONTENT_MATCHER,
                                XSS_PAYLOAD_HTML_FILE,
                                FILE_PARAMETERS_EXTENDED,
                                VulnerabilityType.XSS_HTML_FILE);
            }
        } catch (IOException e) {
            throw new FileUploadException(e);
        }
        return result;
    }
}
