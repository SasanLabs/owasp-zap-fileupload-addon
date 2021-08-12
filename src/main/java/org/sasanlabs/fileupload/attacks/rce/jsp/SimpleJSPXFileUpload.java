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

import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.sasanlabs.fileupload.FileUploadUtils;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.model.FileExtensionOperation;
import org.sasanlabs.fileupload.attacks.model.FileInformationProvider;
import org.sasanlabs.fileupload.attacks.model.FileInformationProviderBuilder;
import org.sasanlabs.fileupload.attacks.model.VulnerabilityType;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.MD5HashResponseMatcher;

/** @author KSASAN preetkaran20@gmail.com */
public class SimpleJSPXFileUpload extends AttackVector {

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

    private static final List<FileInformationProvider> FILE_PARAMETERS_EXTENDED =
            Arrays.asList(
                    new FileInformationProviderBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JspX")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSPX")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JspX")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSPX")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JspX")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSPX")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JspX")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileInformationProviderBuilder(JSPX_UPLOADED_FILE_BASE_NAME)
                            .withExtension("JSPX")
                            .withContentType("application/x-jsp")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build());

    // Need to validate
    // application/x-httpd-jsp
    // text/x-jsp
    private static final List<FileInformationProvider> FILE_PARAMETERS =
            FileUploadUtils.getFileInformationProvidersDefaultJsp(
                    JSPX_UPLOADED_FILE_BASE_NAME, FileUploadUtils.JSPX_FILE_EXTENSION);

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        boolean result =
                this.genericAttackExecutor(
                        fileUploadAttackExecutor,
                        JSPX_PAYLOAD,
                        FILE_PARAMETERS,
                        CONTENT_MATCHER,
                        VulnerabilityType.RCE_JSPX_FILE);
        if (!result
                && fileUploadAttackExecutor
                        .getFileUploadScanRule()
                        .getAttackStrength()
                        .equals(AttackStrength.INSANE)) {
            result =
                    this.genericAttackExecutor(
                            fileUploadAttackExecutor,
                            JSPX_PAYLOAD,
                            FILE_PARAMETERS_EXTENDED,
                            CONTENT_MATCHER,
                            VulnerabilityType.RCE_JSPX_FILE);
        }

        return result;
    }
}
