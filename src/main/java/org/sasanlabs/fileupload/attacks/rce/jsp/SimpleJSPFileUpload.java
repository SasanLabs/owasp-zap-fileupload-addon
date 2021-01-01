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
package org.sasanlabs.fileupload.attacks.rce.jsp;

import static org.sasanlabs.fileupload.FileUploadUtils.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.beans.FileExtensionOperation;
import org.sasanlabs.fileupload.attacks.beans.FileParameter;
import org.sasanlabs.fileupload.attacks.beans.FileParameterBuilder;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.MD5HashResponseMatcher;

/** @author KSASAN preetkaran20@gmail.com */

// TODO check if we need to have case sensitive extensions like JsP or jSP or hTML or HtmL or hTmL
// etc
public class SimpleJSPFileUpload implements AttackVector {

    private static final String JSP_UPLOADED_FILE_BASE_NAME = "SimpleJSPFileUpload_";
    /**
     * using tag based attack too here. e.g. "${'InJeCtTe'}" _jsp_gen_payload_expression_lang in
     * burp extension
     */
    private static final String JSP_PAYLOAD =
            "<% out.print(\"SimpleJSPFileUpload\"); out.print(\"_SasanLabs_ZAP_Identifier\"); %>";

    private static final ContentMatcher CONTENT_MATCHER =
            new MD5HashResponseMatcher("SimpleJSPFileUpload_SasanLabs_ZAP_Identifier");

    private static final List<FileParameter> FILE_PARAMETERS_EXTENDED =
            Arrays.asList(
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSP")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Jsp")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSP")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSP")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("Jsp")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSP")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build());

    private static final List<FileParameter> FILE_PARAMETERS_DEFAULT =
            Arrays.asList(
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jsp")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jsp")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jsp" + NULL_BYTE_CHARACTER)
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jsp" + NULL_BYTE_CHARACTER)
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jsp%00")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(JSP_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jsp%00")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build());

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        boolean result = false;
        try {
            result =
                    this.genericAttackExecutor(
                            fileUploadAttackExecutor,
                            CONTENT_MATCHER,
                            JSP_PAYLOAD,
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
                                    JSP_PAYLOAD,
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
