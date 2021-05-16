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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.FileUploadScanRule;
import org.sasanlabs.fileupload.attacks.beans.FileParameter;
import org.sasanlabs.fileupload.attacks.beans.VulnerabilityType;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.i18n.FileUploadI18n;
import org.sasanlabs.fileupload.locator.URILocatorImpl;
import org.sasanlabs.fileupload.matcher.ContentMatcher;

/**
 * {@code AttackVector} interface is implemented by various attack vector implementations e.g. XSS,
 * JSP RCE, PHP RCE etc.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public interface AttackVector {

    /**
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
                newMsg.getRequestHeader().getURI().toString(),
                newMsg.getRequestBody().toString(),
                payload,
                FileUploadI18n.getMessage(vulnerabilityType.getMessageKey() + ".refs"),
                FileUploadI18n.getMessage(vulnerabilityType.getMessageKey() + ".soln"),
                preflight);
    }

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
        String originalFileName = null;
        String originalContentType = null;
        for (NameValuePair nameValuePair : nameValuePairs) {
            if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME) {
                originalFileName = nameValuePair.getValue();
            } else if (nameValuePair.getType()
                    == NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE) {
                originalContentType = nameValuePair.getValue();
            }
        }
        for (FileParameter fileParameter : fileParameters) {
            if (fileUploadAttackExecutor.getFileUploadScanRule().isStop()) {
                return false;
            }
            fileUploadAttackExecutor.getFileUploadScanRule().decreaseRequestCount();
            HttpMessage newMsg = originalMsg.cloneRequest();
            List<NameValuePair> newNameValuePairs = new ArrayList<>();
            List<String> newParamNames = new ArrayList<>();
            List<String> newParamValues = new ArrayList<>();
            for (int i = 0; i < nameValuePairs.size(); i++) {
                NameValuePair nameValuePair = nameValuePairs.get(i);
                if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME
                        || nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_PARAM
                        || nameValuePair.getType()
                                == NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE) {
                    newNameValuePairs.add(nameValuePair);
                    newParamNames.add(nameValuePair.getName());
                } else {
                    continue;
                }
                if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME) {
                    newParamValues.add(fileParameter.getFileName(originalFileName));
                } else if (nameValuePair.getType()
                        == NameValuePair.TYPE_MULTIPART_DATA_FILE_PARAM) {
                    newParamValues.add(payload);
                } else if (nameValuePair.getType()
                        == NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE) {
                    newParamValues.add(fileParameter.getContentType(originalContentType));
                }
            }
            fileUploadScanRule.setParameters(
                    newMsg, newNameValuePairs, newParamNames, newParamValues);
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

    // Flexi Injector is quite easy as in case uploaded files are base64 encoded or
    // something like that
    // the scanner asks for the input file and then compare the request (whcih might
    // be encoded) with the input and then operate accordingly.

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
