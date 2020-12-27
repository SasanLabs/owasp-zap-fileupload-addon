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
package org.sasanlabs.fileupload.attacks;

import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.FileUploadScanRule;
import org.sasanlabs.fileupload.attacks.rce.jsp.ImageBasedJSPRemoteCodeExecution;
import org.sasanlabs.fileupload.attacks.rce.jsp.PlainOldJSPRemoteCodeExecution;
import org.sasanlabs.fileupload.attacks.rce.jsp.PlainOldJSPXRemoteCodeExecution;
import org.sasanlabs.fileupload.attacks.xss.HtmlFileUpload;
import org.sasanlabs.fileupload.exception.FileUploadException;

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
    private List<AttackVector> attackVectors =
            Arrays.asList(
                    new HtmlFileUpload(),
                    new PlainOldJSPRemoteCodeExecution(),
                    new PlainOldJSPXRemoteCodeExecution(),
                    new ImageBasedJSPRemoteCodeExecution());

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
            if (this.fileUploadScanRule.isStop()) {
                return false;
            } else {
                if (attackVector.execute(this)) {
                    return true;
                }
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
