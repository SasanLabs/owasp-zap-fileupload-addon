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
package org.sasanlabs.fileupload.attacks.impl;

import static org.sasanlabs.fileupload.Constants.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.sasanlabs.fileupload.Constants;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.FileUploadException;
import org.sasanlabs.fileupload.attacks.beans.FileExtensionOperation;
import org.sasanlabs.fileupload.attacks.beans.FileParameter;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.MD5HashResponseMatcher;

/** @author KSASAN preetkaran20@gmail.com */

// TODO check if we need to have case sensitive extensions like JsP or jSP or hTML or HtmL or hTmL
// etc
public class PlainOldJSPRemoteCodeExecution implements AttackVector {

    private static final String JSP_UPLOADED_FILE_BASE_NAME = "PlainOldJSPRemoteCodeExecution_";
    private static final String JSP_PAYLOAD =
            "<% out.print(\"PlainOldJSPRemoteCodeExecution\"); out.print(\"_SasanLabs_ZAP_Identifier\"); %>";

    private static final ContentMatcher CONTENT_MATCHER =
            new MD5HashResponseMatcher("PlainOldJSPRemoteCodeExecution_SasanLabs_ZAP_Identifier");

    private static final List<FileParameter> FILE_PARAMETERS =
            Arrays.asList(
                    new FileParameter("jsp", Constants.EMPTY_STRING),
                    new FileParameter("jsp", "application/x-jsp"),
                    new FileParameter(
                            "jsp",
                            Constants.EMPTY_STRING,
                            FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "jsp",
                            "application/x-jsp",
                            FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "jsp" + NULL_BYTE_CHARACTER,
                            Constants.EMPTY_STRING,
                            FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION),
                    new FileParameter(
                            "jsp" + NULL_BYTE_CHARACTER,
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
                            JSP_PAYLOAD,
                            JSP_UPLOADED_FILE_BASE_NAME,
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
