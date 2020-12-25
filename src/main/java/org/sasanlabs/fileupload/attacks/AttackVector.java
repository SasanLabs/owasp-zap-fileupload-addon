package org.sasanlabs.fileupload.attacks;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.FileUploadScanRule;
import org.sasanlabs.fileupload.attacks.beans.FileParameter;
import org.sasanlabs.fileupload.configuration.URILocatorImpl;
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
     * @return
     * @throws IOException
     */
    default HttpMessage executePreflightRequest(
            HttpMessage modifiedMsg, FileUploadScanRule fileUploadScanRule) throws IOException {
        HttpMessage preflightMsg = new HttpMessage();
        preflightMsg.getRequestHeader().setURI(new URILocatorImpl().get(modifiedMsg));
        preflightMsg.getRequestHeader().setMethod("GET");
        preflightMsg.getRequestHeader().setCookies(modifiedMsg.getRequestHeader().getHttpCookies());
        fileUploadScanRule.sendAndRecieve(preflightMsg);
        return preflightMsg;
    }

    default boolean genericAttackExecutor(
            FileUploadAttackExecutor fileUploadAttackExecutor,
            ContentMatcher md5HashResponseMatcher,
            String payload,
            String baseFileName,
            List<FileParameter> fileParameters)
            throws IOException {
        List<NameValuePair> nameValuePairs = fileUploadAttackExecutor.getVariant().getParamList();
        HttpMessage originalMsg = fileUploadAttackExecutor.getOriginalHttpMessage();
        FileUploadScanRule fileUploadScanRule = fileUploadAttackExecutor.getFileUploadScanRule();
        String originalFileName = null;
        for (NameValuePair nameValuePair : nameValuePairs) {
            if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME) {
                originalFileName = nameValuePair.getValue();
            }
        }
        for (FileParameter fileParameter : fileParameters) {
            HttpMessage newMsg = originalMsg.cloneRequest();
            for (NameValuePair nameValuePair : nameValuePairs) {
                if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME) {
                    fileUploadScanRule.setParameter(
                            newMsg,
                            nameValuePair,
                            nameValuePair.getName(),
                            fileParameter.getFileName(originalFileName, baseFileName));
                }
                if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_PARAM) {
                    fileUploadScanRule.setParameter(
                            newMsg, nameValuePair, nameValuePair.getName(), payload);
                }
                if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE) {
                    fileUploadScanRule.setParameter(
                            newMsg,
                            nameValuePair,
                            nameValuePair.getName(),
                            fileParameter.getContentType());
                }
            }
            fileUploadScanRule.sendAndRecieve(newMsg);
            HttpMessage preflightMsg = this.executePreflightRequest(newMsg, fileUploadScanRule);
            if (md5HashResponseMatcher.match(preflightMsg)) {
                return true;
            }
        }
        return false;
    }

    // Flexi Injector is quite easy as in case uploaded files are base64 encoded or
    // something like that
    // the scanner asks for the input file and then compare the request (whcih might
    // be encoded) with the input and then operate accordingly.
    default boolean executeAttackAndRaiseAlert(
            HttpMessage originalMsg,
            HttpMessage modifiedMsg,
            FileUploadScanRule fileUploadScanRule,
            ContentMatcher responseMatcher)
            throws URIException, NullPointerException, IOException {
        HttpMessage preflightMsg = new HttpMessage();
        preflightMsg.getRequestHeader().setURI(new URILocatorImpl().get(modifiedMsg));
        preflightMsg.getRequestHeader().setMethod("GET");
        preflightMsg.getRequestHeader().setCookies(modifiedMsg.getRequestHeader().getHttpCookies());
        fileUploadScanRule.sendAndRecieve(preflightMsg);

        // For XSS only
        String headerValue = preflightMsg.getResponseHeader().getHeader("Content-Disposition");
        if (headerValue == null || headerValue.equals("inline")) {
            // check content disposition
            // preflightMsg.getResponseHeader().
            try {
                MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                byte[] digest =
                        messageDigest.digest(
                                Base64.getEncoder()
                                        .encode(preflightMsg.getResponseBody().getBytes()));
                return Arrays.equals(
                        digest,
                        messageDigest.digest(
                                Base64.getEncoder()
                                        .encode(modifiedMsg.getResponseBody().getBytes())));
            } catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        // Try finding the URL in msg
        // if found
        // do a preflight request
        // compare the results
        // if not
        // check if static url is selected
        // do prefligh request with the same file name
        // compare result
        // try guessing the name
        // if found compare result
        return false;
    };

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
