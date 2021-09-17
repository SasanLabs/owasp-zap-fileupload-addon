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
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.FileUploadScanRule;
import org.sasanlabs.fileupload.attacks.antivirus.EicarAntivirusTestFileUpload;
import org.sasanlabs.fileupload.attacks.model.FileInformationProvider;
import org.sasanlabs.fileupload.attacks.model.VulnerabilityType;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.function.ConsumerWithException;
import org.sasanlabs.fileupload.i18n.FileUploadI18n;
import org.sasanlabs.fileupload.locator.URILocatorImpl;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.zaproxy.zap.core.scanner.InputVector.PayloadFormat;
import org.zaproxy.zap.core.scanner.InputVectorBuilder;

/**
 * {@code AttackVector} is an abstract template class for file upload attacks. This class also
 * contains few utility methods for raising alerts and firing Http requests.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public abstract class AttackVector {

    private static final Logger LOGGER = LogManager.getLogger(AttackVector.class);

    /**
     * @param httpMsg, HttpMessage containing uploaded file's request and response
     * @param fileName, uploaded file's name
     * @param sendAndRecieveHttpMsg, consumer to send and Receive {@code HttpMessage}
     * @return URI of the uploaded file
     * @throws FileUploadException, in case of failure in retrieval of uploaded file.
     */
    protected URI getUploadedFileURI(
            HttpMessage httpMsg,
            String fileName,
            ConsumerWithException<HttpMessage, IOException> sendAndRecieveHttpMsg)
            throws FileUploadException {
        return new URILocatorImpl()
                .get(httpMsg, fileName, (httpmessage) -> sendAndRecieveHttpMsg.accept(httpmessage));
    }

    /**
     * In general, for file upload functionalities, file is uploaded from one endpoint and retrieved
     * from another endpoint. This method finds the url of the file retrieval endpoint, invokes that
     * endpoint to retrieve the uploaded file and returns the {@code HttpMessage}.
     *
     * @param httpMsg, HttpMessage containing uploaded file's request and response
     * @param fileName, uploaded file's name
     * @param sendAndRecieveHttpMsg, consumer to send and Receive {@code HttpMessage}
     * @return {@code HttpMessage}, representing the file retrieval request and response. It returns
     *     {@code null} if unable to find the uploaded file.
     * @throws FileUploadException, in case of failure in retrieval of uploaded file.
     */
    private HttpMessage getUploadedFileHttpMessage(
            HttpMessage httpMsg,
            String fileName,
            ConsumerWithException<HttpMessage, IOException> sendAndRecieveHttpMsg)
            throws FileUploadException {
        HttpMessage uploadedFileRetrievalMsg = new HttpMessage();
        URI uri;
        try {
            uri = this.getUploadedFileURI(httpMsg, fileName, sendAndRecieveHttpMsg);
            if (Objects.isNull(uri)) {
                return null;
            }

            uploadedFileRetrievalMsg.getRequestHeader().setURI(uri);
            uploadedFileRetrievalMsg.getRequestHeader().setMethod("GET");
            uploadedFileRetrievalMsg
                    .getRequestHeader()
                    .setCookies(httpMsg.getRequestHeader().getHttpCookies());
            uploadedFileRetrievalMsg.setRequestBody("");
            sendAndRecieveHttpMsg.accept(uploadedFileRetrievalMsg);
        } catch (IOException e) {
            throw new FileUploadException(
                    "Following exception occurred while retrieving uploaded file ", e);
        }
        return uploadedFileRetrievalMsg;
    }

    /**
     * This method is used to raise the alert with the provided details.
     *
     * @param fileUploadScanRule, File Upload scan rule
     * @param vulnerabilityType, type of the vulnerability exposed by the {@code modifiedMsg}
     * @param modifiedMsg, {@code HttpMessage} representing the uploaded file's request and
     *     response.
     * @param uploadedFileRetrievalMsg, {@code HttpMessage} representing the file retrieval's
     *     request and response.
     */
    private void raiseAlert(
            FileUploadScanRule fileUploadScanRule,
            VulnerabilityType vulnerabilityType,
            HttpMessage modifiedMsg,
            HttpMessage uploadedFileRetrievalMsg) {
        fileUploadScanRule.raiseAlert(
                vulnerabilityType.getAlertLevel(),
                Alert.CONFIDENCE_MEDIUM,
                FileUploadI18n.getMessage(vulnerabilityType.getMessageKey() + ".name"),
                FileUploadI18n.getMessage(vulnerabilityType.getMessageKey() + ".desc"),
                uploadedFileRetrievalMsg.getRequestHeader().getURI().toString(),
                modifiedMsg.getRequestHeader().toString() + modifiedMsg.getRequestBody().toString(),
                MessageFormat.format(
                        FileUploadI18n.getMessage("fileupload.alert.attack"),
                        uploadedFileRetrievalMsg.getRequestHeader().toString()
                                + uploadedFileRetrievalMsg.getRequestBody().toString(),
                        uploadedFileRetrievalMsg.getResponseHeader().toString()
                                + uploadedFileRetrievalMsg.getResponseBody().toString()),
                FileUploadI18n.getMessage(vulnerabilityType.getMessageKey() + ".refs"),
                FileUploadI18n.getMessage(vulnerabilityType.getMessageKey() + ".soln"),
                modifiedMsg);
    }

    /**
     * Utility method to upload the provided file. It modifies the {@code HttpMessage} based on the
     * provided {@code fileInformationProvider}, {@code payload} and then sends the HttpMessage.
     *
     * @param fileUploadAttackExecutor, holds original {@code HttpMessage}, {@code NameValuePair}
     *     and {@code FileUploadScanRule}
     * @param payload, the content of the file which needs to be uploaded
     * @param fileInformationProvider, the modifications provider for a file.
     * @return {@code HttpMessage}, representing the file retrieval request and response. It returns
     *     {@code null} if unable to find the uploaded file.
     * @throws FileUploadException, in case of any failure while uploadingfile.
     */
    private HttpMessage uploadFile(
            FileUploadAttackExecutor fileUploadAttackExecutor,
            String payload,
            FileInformationProvider fileInformationProvider)
            throws FileUploadException {
        List<NameValuePair> nameValuePairs = fileUploadAttackExecutor.getNameValuePairs();
        HttpMessage originalMsg = fileUploadAttackExecutor.getOriginalHttpMessage();
        FileUploadScanRule fileUploadScanRule = fileUploadAttackExecutor.getFileUploadScanRule();
        HttpMessage uploadFileMsg = originalMsg.cloneRequest();
        InputVectorBuilder inputVectorBuilder =
                fileUploadAttackExecutor.getFileUploadScanRule().getBuilder();
        for (NameValuePair nameValuePair : nameValuePairs) {
            if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME) {
                inputVectorBuilder.setValue(
                        nameValuePair,
                        fileInformationProvider.getFileName(
                                fileUploadAttackExecutor.getOriginalFileName()),
                        PayloadFormat.ALREADY_ESCAPED);
            } else if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_PARAM) {
                inputVectorBuilder.setValue(nameValuePair, payload, PayloadFormat.ALREADY_ESCAPED);
            } else if (nameValuePair.getType()
                    == NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE) {
                inputVectorBuilder.setValue(
                        nameValuePair,
                        fileInformationProvider.getContentType(
                                fileUploadAttackExecutor.getOriginalContentType()),
                        PayloadFormat.ALREADY_ESCAPED);
            }
        }
        fileUploadScanRule.setParameters(uploadFileMsg, inputVectorBuilder.build());
        try {
            fileUploadScanRule.sendAndReceive(uploadFileMsg);
        } catch (IOException ex) {
            throw new FileUploadException("Exception occurred while sending modified message", ex);
        }
        return uploadFileMsg;
    }

    /**
     * Generic Attack Executor utility method is used to execute attack by uploading a file, finding
     * uploaded file and then raising alerts in case attack is successful.
     *
     * @param fileUploadAttackExecutor, holds original {@code HttpMessage}, {@code NameValuePair}
     *     and {@code FileUploadScanRule}
     * @param payload, content of the file which will be uploaded
     * @param fileInformationProvider, provides information about modifications to the file.
     * @param contentMatcher, for matching the uploaded file's content with expected file content.
     * @param vulnerabilityType, type of the vulnerability in case attack is successful
     * @return {@code True} if attack is successful, else {@code False}
     */
    private boolean genericAttackExecutor(
            FileUploadAttackExecutor fileUploadAttackExecutor,
            String payload,
            FileInformationProvider fileInformationProvider,
            ContentMatcher contentMatcher,
            VulnerabilityType vulnerabilityType) {
        try {
            HttpMessage uploadFileMsg =
                    this.uploadFile(fileUploadAttackExecutor, payload, fileInformationProvider);
            HttpMessage retrieveUploadedFile =
                    this.getUploadedFileHttpMessage(
                            uploadFileMsg,
                            fileUploadAttackExecutor.getOriginalFileName(),
                            fileUploadAttackExecutor.getFileUploadScanRule()::sendAndReceive);
            if (Objects.nonNull(retrieveUploadedFile)
                    && contentMatcher.match(retrieveUploadedFile)) {
                raiseAlert(
                        fileUploadAttackExecutor.getFileUploadScanRule(),
                        vulnerabilityType,
                        uploadFileMsg,
                        retrieveUploadedFile);
                return true;
            }
        } catch (FileUploadException e) {
            LOGGER.debug("Following exception occurred: ", e);
        }
        return false;
    }

    /**
     * Generic Attack Executor utility method is used to execute attack by uploading files, finding
     * uploaded files and then raising alerts in case attack is successful.
     *
     * @param fileUploadAttackExecutor, holds original {@code HttpMessage}, {@code NameValuePair}
     *     and {@code FileUploadScanRule}
     * @param payload, content of the file which will be uploaded
     * @param fileInformationProviders, provides list of file property modification details.
     * @param contentMatcher, for matching the uploaded file's content with expected file content.
     * @param vulnerabilityType, type of the vulnerability in case attack is successful
     * @return {@code True} if attack is successful, else {@code False}
     */
    protected boolean genericAttackExecutor(
            FileUploadAttackExecutor fileUploadAttackExecutor,
            String payload,
            List<FileInformationProvider> fileInformationProviders,
            ContentMatcher contentMatcher,
            VulnerabilityType vulnerabilityType) {
        for (FileInformationProvider fileInformationProvider : fileInformationProviders) {
            if (fileUploadAttackExecutor.getFileUploadScanRule().isStop()) {
                return false;
            }
            fileUploadAttackExecutor.getFileUploadScanRule().decreaseRequestCount();
            if (this.genericAttackExecutor(
                    fileUploadAttackExecutor,
                    payload,
                    fileInformationProvider,
                    contentMatcher,
                    vulnerabilityType)) {
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
     * @param fileUploadAttackExecutor, holds original {@code HttpMessage}, {@code NameValuePair}
     *     and {@code FileUploadScanRule}
     * @return {@code true} if attack is successful else {@code false}
     * @throws FileUploadException, in case of any failure while executing attack
     */
    public abstract boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException;
}
