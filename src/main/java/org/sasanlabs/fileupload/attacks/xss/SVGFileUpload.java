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
package org.sasanlabs.fileupload.attacks.xss;

import static org.sasanlabs.fileupload.FileUploadUtils.NULL_BYTE_CHARACTER;

import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.model.FileExtensionOperation;
import org.sasanlabs.fileupload.attacks.model.FileInformationProvider;
import org.sasanlabs.fileupload.attacks.model.FileInformationProviderBuilder;
import org.sasanlabs.fileupload.attacks.model.VulnerabilityType;

/**
 * {@code SVGFileUpload} attack vector will upload {@code svg} and its various different extension
 * schemes in order to evaluate whether the application is vulnerable to {@code XSS} vulnerability.
 * <br>
 * General logic is if Application is allowing to upload {@code svg} file and while downloading the
 * same file it is shown {@code inline} by the browser which is controlled by {@code
 * Content-Disposition} header then it is vulnerable to Stored XSS.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class SVGFileUpload extends AttackVector {

    private static final String XSS_UPLOADED_FILE_BASE_NAME = "SVGFileUpload_XSS_";
    private static final String XSS_PAYLOAD_SVG_FILE =
            "<svg version=\"1.1\" baseProfile=\"full\" xmlns=\"http://www.w3.org/2000/svg\">\n"
                    + "<script type=\"text/javascript\">\n"
                    + "alert(\"SVGFileUpload_XSS_Testing\");\n"
                    + "</script>\n"
                    + "</svg>";

    // Extended list for breaking black-listing strategy.
    private static final List<FileInformationProvider> FILE_PARAMETERS_EXTENDED =
            Arrays.asList(
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Svg")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("SvG")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("SVG")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Svgz")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("SvGz")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("SVGZ")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("XML")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Svg")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("SvG")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("SVG")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Svgz")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("SvGz")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("SVGZ")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xML")
                            .withContentType("text/xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Xml")
                            .withContentType("text/xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("XML")
                            .withContentType("text/xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Svg")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("SVG")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Svgz")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("SVGZ")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xML")
                            .withContentType("text/xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("XML")
                            .withContentType("text/xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build());

    /**
     * Extensions working with SVG payload for XSS: svg,html,xml,htm,xhtml,Null byte
     * (assumption),shtml,svgz,dhtml Extensions not working: png,gif,swf,pdf,mvg,xbm,ssi,jpeg
     *
     * <p>Didn't pick html and its related variant extensions because those attack vectors will be
     * covered under {@link HtmlFileUpload}.
     */
    private static final List<FileInformationProvider> FILE_PARAMETERS_DEFAULT =
            Arrays.asList(
                    // Not adding empty extension for svg because it is not working in browsers
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("svg")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("svgz")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("svg")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xml")
                            .withContentType("text/xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("svgz")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("svg")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("svgz")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("svg" + NULL_BYTE_CHARACTER)
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("svg" + NULL_BYTE_CHARACTER)
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("svg%00")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(XSS_UPLOADED_FILE_BASE_NAME)
                            .withExtension("svg%00")
                            .withContentType("image/svg+xml")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build());

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor) {
        boolean result =
                this.genericAttackExecutor(
                        fileUploadAttackExecutor,
                        XSS_PAYLOAD_SVG_FILE,
                        FILE_PARAMETERS_DEFAULT,
                        HtmlFileUpload.CONTENT_MATCHER,
                        VulnerabilityType.XSS_SVG_FILE);
        if (!result
                && fileUploadAttackExecutor
                        .getFileUploadScanRule()
                        .getAttackStrength()
                        .equals(AttackStrength.INSANE)) {
            result =
                    this.genericAttackExecutor(
                            fileUploadAttackExecutor,
                            XSS_PAYLOAD_SVG_FILE,
                            FILE_PARAMETERS_EXTENDED,
                            HtmlFileUpload.CONTENT_MATCHER,
                            VulnerabilityType.XSS_SVG_FILE);
        }

        return result;
    }
}
