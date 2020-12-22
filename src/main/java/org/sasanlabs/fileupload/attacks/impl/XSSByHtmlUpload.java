package org.sasanlabs.fileupload.attacks.impl;

import static org.sasanlabs.fileupload.Constants.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.Constants;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.FileUploadException;
import org.sasanlabs.fileupload.attacks.beans.FileParameter;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.MD5HashResponseMatcher;

/** @author preetkaran20@gmail.com KSASAN */
public class XSSByHtmlUpload implements AttackVector {

    private static final String XSS_UPLOADED_FILE_BASE_NAME = "XSSByHtmlUpload_";
    private static final String XSS_PAYLOAD_HTML_FILE =
            "<html><head></head><body>Testing XSS</body></html>";

    private static final ContentMatcher CONTENT_MATCHER =
            new MD5HashResponseMatcher(
                    httpMsg -> isContentDispositionInline(httpMsg), XSS_PAYLOAD_HTML_FILE);

    private static boolean isContentDispositionInline(HttpMessage preflightMsg) {
        String headerValue = preflightMsg.getResponseHeader().getHeader("Content-Disposition");
        if (headerValue == null
                || headerValue.trim().equals(Constants.EMPTY_STRING)
                || headerValue.equals("inline")) {
            return true;
        }
        return false;
    }

    private static final List<FileParameter> FILE_PARAMETERS =
            Arrays.asList(
                    new FileParameter("htm", Constants.EMPTY_STRING),
                    new FileParameter("html", Constants.EMPTY_STRING),
                    new FileParameter("xhtml", Constants.EMPTY_STRING),
                    new FileParameter("htm", "text/html"),
                    new FileParameter("html", "text/html"),
                    new FileParameter("xhtml", "text/html"),
                    new FileParameter("htm", "text/plain"),
                    new FileParameter("html", "text/plain"),
                    new FileParameter("xhtml", "text/plain"),
                    new FileParameter("htm.", "text/html", true),
                    new FileParameter("html.", "text/html", true),
                    new FileParameter("xhtml.", "text/html", true),
                    new FileParameter("htm." + NULL_BYTE_CHARACTER, "text/html", true),
                    new FileParameter("html." + NULL_BYTE_CHARACTER, "text/html", true),
                    new FileParameter("xhtml." + NULL_BYTE_CHARACTER, "text/html", true),
                    new FileParameter("htm." + NULL_BYTE_CHARACTER, "text/plain", true),
                    new FileParameter("html." + NULL_BYTE_CHARACTER, "text/plain", true),
                    new FileParameter("xhtml." + NULL_BYTE_CHARACTER, "text/plain", true));

    /**
     * @throws FileUploadException
     * @throws IOException
     */
    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        boolean result = false;
        try {
            result =
                    this.genericAttackExecutor(
                            fileUploadAttackExecutor,
                            CONTENT_MATCHER,
                            XSS_PAYLOAD_HTML_FILE,
                            XSS_UPLOADED_FILE_BASE_NAME,
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
