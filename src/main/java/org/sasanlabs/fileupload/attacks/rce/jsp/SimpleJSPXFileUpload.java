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
import org.sasanlabs.fileupload.attacks.beans.VulnerabilityType;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.MD5HashResponseMatcher;

/** @author KSASAN preetkaran20@gmail.com */
public class SimpleJSPXFileUpload implements AttackVector {

    private static final String JSPX_UPLOADED_FILE_BASE_NAME = "SimpleJSPXFileUpload_";
    // Payload from resource file: "jspx_payload.jspx"
    private static final String JSPX_PAYLOAD =
            "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\"  version=\"1.2\"> \n"
                    + "<jsp:directive.page contentType=\"text/html\" pageEncoding=\"UTF-8\" /> \n"
                    + "<jsp:scriptlet> \n"
                    + "    out.print(\"SimpleJSPXFileUpload_\"); \n"
                    + "	 out.print(\"SasanLabs_ZAP_Identifier\");"
                    + "</jsp:scriptlet> \n"
                    + "</jsp:root>";

    private static final ContentMatcher CONTENT_MATCHER =
            new MD5HashResponseMatcher("SimpleJSPXFileUpload_SasanLabs_ZAP_Identifier");

    private static final List<FileParameter> FILE_PARAMETERS_EXTENDED =
            Arrays.asList(
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JspX")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSPX")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JspX")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSPX")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JspX")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSPX")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JspX")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSPX")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build());

    // Need to validate
    // application/x-httpd-jsp
    // text/x-jsp
    private static final List<FileParameter> FILE_PARAMETERS =
            Arrays.asList(
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jspx")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jspx")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jspx")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jspx")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jspx" + NULL_BYTE_CHARACTER)
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jspx" + NULL_BYTE_CHARACTER)
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jspx%00")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("jspx%00")
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
                            JSPX_PAYLOAD,
                            FILE_PARAMETERS,
                            VulnerabilityType.RCE_JSPX_FILE);
            if (!result
                    && fileUploadAttackExecutor
                            .getFileUploadScanRule()
                            .getAttackStrength()
                            .equals(AttackStrength.INSANE)) {
                result =
                        this.genericAttackExecutor(
                                fileUploadAttackExecutor,
                                CONTENT_MATCHER,
                                JSPX_PAYLOAD,
                                FILE_PARAMETERS_EXTENDED,
                                VulnerabilityType.RCE_JSPX_FILE);
            }
        } catch (IOException e) {
            throw new FileUploadException(e);
        }
        return result;
    }
}
