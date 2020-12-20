package org.sasanlabs.fileupload.attacks;

import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.FileUploadScanRule;
import org.sasanlabs.fileupload.attacks.impl.XSSByHtmlUpload;

/**
 * {@code FileUploadAttackExecutor} class is used to find File Upload vulnerability by executing
 * list of attack vector.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class FileUploadAttackExecutor {

    private HttpMessage originalHttpMessage;
    private FileUploadScanRule fileUploadScanRule;
    private Variant variant;
    private List<AttackVector> attackVectors = Arrays.asList(new XSSByHtmlUpload());

    public FileUploadAttackExecutor(
            HttpMessage originalHttpMessage,
            FileUploadScanRule fileUploadScanRule,
            Variant variant) {
        super();
        this.originalHttpMessage = originalHttpMessage;
        this.fileUploadScanRule = fileUploadScanRule;
        this.variant = variant;
    }

    public boolean executeAttack() throws FileUploadException {
        for (AttackVector attackVector : attackVectors) {
            if (attackVector.execute(this)) {
                return true;
            }
        }
        return false;
    }

    public HttpMessage getOriginalHttpMessage() {
        return originalHttpMessage;
    }

    public FileUploadScanRule getFileUploadScanRule() {
        return fileUploadScanRule;
    }

    public Variant getVariant() {
        return variant;
    }

    public List<AttackVector> getAttackVectors() {
        return attackVectors;
    }
}
