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
package org.sasanlabs.fileupload.attacks;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.List;
import java.util.Objects;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.FileUploadScanRule;
import org.sasanlabs.fileupload.attacks.model.FileParameter;
import org.sasanlabs.fileupload.attacks.model.VulnerabilityType;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.i18n.FileUploadI18n;
import org.sasanlabs.fileupload.locator.URILocatorImpl;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.zaproxy.zap.core.scanner.InputVector.PayloadFormat;
import org.zaproxy.zap.core.scanner.InputVectorBuilder;

/**
 * {@code AttackVector} is a common interface for file upload attacks.
 * This interface also contains few utility methods for raising alerts and firing
 * Preflight requests.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public interface AttackVector {

    /**
     * In general file upload functionalities, file is uploaded from a one endpoint and retrieved
     * from a another endpoint which makes it extremely difficult to automate. Preflight request is
     * the request to another endpoint for retrieval of uploaded file.
     *
     * <p>This method finds the url of the file retrieval endpoint, invokes that endpoint and
     * returns the {@code HttpMessage}.
     *
     * @param modifiedMsg
     * @param fileUploadScanRule
     * @return httpMessage of preflight request
     * @throws IOException
     * @throws FileUploadException
     */
    default HttpMessage executePreflightRequest(
            HttpMessage modifiedMsg, String fileName, FileUploadScanRule fileUploadScanRule)
            throws IOException, FileUploadException {
        HttpMessage preflightMsg = new HttpMessage();
        URI uri =
                new URILocatorImpl()
                        .get(
                                modifiedMsg,
                                fileName,
                                (httpmessage) -> fileUploadScanRule.sendAndRecieve(httpmessage));
        if (Objects.isNull(uri)) {
            return null;
        }

        preflightMsg.getRequestHeader().setURI(uri);
        preflightMsg.getRequestHeader().setMethod("GET");
        preflightMsg.getRequestHeader().setCookies(modifiedMsg.getRequestHeader().getHttpCookies());
        fileUploadScanRule.sendAndRecieve(preflightMsg);
        return preflightMsg;
    }

    /**
     * This method is used to raise the alert if a vulnerability is found.
     *
     * @param fileUploadScanRule
     * @param vulnerabilityType
     * @param payload
     * @param newMsg
     * @param preflight
     */
    default void raiseAlert(
            FileUploadScanRule fileUploadScanRule,
            VulnerabilityType vulnerabilityType,
            String payload,
            HttpMessage newMsg,
            HttpMessage preflight) {
        fileUploadScanRule.raiseAlert(
                vulnerabilityType.getAlertLevel(),
                Alert.CONFIDENCE_MEDIUM,
                FileUploadI18n.getMessage(vulnerabilityType.getMessageKey() + ".name"),
                FileUploadI18n.getMessage(vulnerabilityType.getMessageKey() + ".desc"),
                preflight.getRequestHeader().getURI().toString(),
                newMsg.getRequestHeader().toString() + newMsg.getRequestBody().toString(),
                MessageFormat.format(
                        FileUploadI18n.getMessage("fileupload.alert.attack"),
                        preflight.getRequestHeader().toString()
                                + preflight.getRequestBody().toString(),
                        preflight.getResponseHeader().toString()
                                + preflight.getResponseBody().toString()),
                FileUploadI18n.getMessage(vulnerabilityType.getMessageKey() + ".refs"),
                FileUploadI18n.getMessage(vulnerabilityType.getMessageKey() + ".soln"),
                newMsg);
    }

    /**
     * For File Upload vulnerability there are 3 important steps: 1. modify the actual {@code
     * HttpMessage} based on the type of attack 2. firing Preflight request 3. response content
     * matching to validate if vulnerability is present or not.
     *
     * <p>This method executes all these steps. It modifies the {@code HttpMessage} based on the
     * {@code fileParameters} then uses {@link #executePreflightRequest(HttpMessage, String,
     * FileUploadScanRule)} to execute the Preflight request and then uses the {@code
     * ContentMatcher} for validating whether vulnerability is present or not.
     *
     * @param fileUploadAttackExecutor
     * @param contentMatcher
     * @param payload
     * @param fileParameters
     * @param vulnerabilityType
     * @return {@code True} if attack is successful else {@code False}
     * @throws IOException
     * @throws FileUploadException
     */
    default boolean genericAttackExecutor(
            FileUploadAttackExecutor fileUploadAttackExecutor,
            ContentMatcher contentMatcher,
            String payload,
            List<FileParameter> fileParameters,
            VulnerabilityType vulnerabilityType)
            throws IOException, FileUploadException {

        List<NameValuePair> nameValuePairs = fileUploadAttackExecutor.getNameValuePairs();
        HttpMessage originalMsg = fileUploadAttackExecutor.getOriginalHttpMessage();
        FileUploadScanRule fileUploadScanRule = fileUploadAttackExecutor.getFileUploadScanRule();
        for (FileParameter fileParameter : fileParameters) {
            if (fileUploadAttackExecutor.getFileUploadScanRule().isStop()) {
                return false;
            }
            fileUploadAttackExecutor.getFileUploadScanRule().decreaseRequestCount();
            HttpMessage newMsg = originalMsg.cloneRequest();
            InputVectorBuilder inputVectorBuilder =
                    fileUploadAttackExecutor.getFileUploadScanRule().getBuilder();
            String originalFileName = null;
            for (NameValuePair nameValuePair : nameValuePairs) {
                if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME) {
                    originalFileName = nameValuePair.getValue();
                    inputVectorBuilder.setValue(
                            nameValuePair,
                            fileParameter.getFileName(originalFileName),
                            PayloadFormat.ALREADY_ESCAPED);
                } else if (nameValuePair.getType()
                        == NameValuePair.TYPE_MULTIPART_DATA_FILE_PARAM) {
                    inputVectorBuilder.setValue(
                            nameValuePair, payload, PayloadFormat.ALREADY_ESCAPED);
                } else if (nameValuePair.getType()
                        == NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE) {
                    String originalContentType = nameValuePair.getValue();
                    inputVectorBuilder.setValue(
                            nameValuePair,
                            fileParameter.getContentType(originalContentType),
                            PayloadFormat.ALREADY_ESCAPED);
                }
            }
            fileUploadScanRule.setParameters(newMsg, inputVectorBuilder.build());
            fileUploadScanRule.sendAndRecieve(newMsg);
            HttpMessage preflightMsg =
                    this.executePreflightRequest(
                            newMsg,
                            fileParameter.getFileName(originalFileName),
                            fileUploadScanRule);
            if (Objects.nonNull(preflightMsg) && contentMatcher.match(preflightMsg)) {
                raiseAlert(fileUploadScanRule, vulnerabilityType, payload, newMsg, preflightMsg);
                return true;
            }
        }
        return false;
    }

    /**
     * TODO: As we are only handling Multipart requests hence in case User interface of Application
     * is using Javascript filereader Api or using some other ways our scan rule will not work.
     *
     * <p>Upload Scanner addon of Burp has handled this by asking the sample request {@link
     * https://github.com/portswigger/upload-scanner#flexiinjector---detecting-requests-with-uploads}
     */

    /**
     * Executes the attack and checks if it is successful or not and then raise alert in case of
     * successful execution.
     *
     * @param fileUploadAttackExecutor
     * @return {@code true} if attack is successful else {@code false}
     * @throws FileUploadException
     */
    boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor) throws FileUploadException;
}
