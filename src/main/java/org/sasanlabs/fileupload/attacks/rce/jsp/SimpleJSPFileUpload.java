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

import java.util.List;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.sasanlabs.fileupload.FileUploadUtils;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.model.FileInformationProvider;
import org.sasanlabs.fileupload.attacks.model.VulnerabilityType;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.MD5HashResponseMatcher;

/** @author KSASAN preetkaran20@gmail.com */
public class SimpleJSPFileUpload extends AttackVector {

    private static final String JSP_UPLOADED_FILE_BASE_NAME = "SimpleJSPFileUpload_";

    private static final String JSP_EL_PAYLOAD =
            "${\"SimpleJSPFileUpload\"}${\"_SasanLabs_ZAP_Identifier\"}";

    private static final String JSP_SCRIPTLET_PAYLOAD =
            "<% out.print(\"SimpleJSPFileUpload\"); out.print(\"_SasanLabs_ZAP_Identifier\"); %>";

    private static final ContentMatcher CONTENT_MATCHER =
            new MD5HashResponseMatcher("SimpleJSPFileUpload_SasanLabs_ZAP_Identifier");

    private static final List<FileInformationProvider> FILE_PARAMETERS_EXTENDED =
            FileUploadUtils.getFileInformationProvidersExtendedJsp(JSP_UPLOADED_FILE_BASE_NAME);
    private static final List<FileInformationProvider> FILE_PARAMETERS_DEFAULT =
            FileUploadUtils.getFileInformationProvidersDefaultJsp(
                    JSP_UPLOADED_FILE_BASE_NAME, FileUploadUtils.JSP_FILE_EXTENSION);

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        boolean result =
                this.genericAttackExecutor(
                        fileUploadAttackExecutor,
                        JSP_SCRIPTLET_PAYLOAD,
                        FILE_PARAMETERS_DEFAULT,
                        CONTENT_MATCHER,
                        VulnerabilityType.RCE_JSP_FILE);
        if (!result) {
            result =
                    this.genericAttackExecutor(
                            fileUploadAttackExecutor,
                            JSP_EL_PAYLOAD,
                            FILE_PARAMETERS_DEFAULT,
                            CONTENT_MATCHER,
                            VulnerabilityType.RCE_JSP_FILE);
        }
        if (!result
                && fileUploadAttackExecutor
                        .getFileUploadScanRule()
                        .getAttackStrength()
                        .equals(AttackStrength.INSANE)) {
            result =
                    this.genericAttackExecutor(
                            fileUploadAttackExecutor,
                            JSP_SCRIPTLET_PAYLOAD,
                            FILE_PARAMETERS_EXTENDED,
                            CONTENT_MATCHER,
                            VulnerabilityType.RCE_JSP_FILE);
            if (!result) {
                result =
                        this.genericAttackExecutor(
                                fileUploadAttackExecutor,
                                JSP_EL_PAYLOAD,
                                FILE_PARAMETERS_EXTENDED,
                                CONTENT_MATCHER,
                                VulnerabilityType.RCE_JSP_FILE);
            }
        }

        return result;
    }
}
