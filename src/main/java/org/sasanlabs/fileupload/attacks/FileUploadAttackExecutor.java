/**
 * Copyright 2023 SasanLabs
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.FileUploadScanRule;
import org.sasanlabs.fileupload.attacks.antivirus.EicarAntivirusTestFileUpload;
import org.sasanlabs.fileupload.attacks.apache.htaccess.HTAccessFileUpload;
import org.sasanlabs.fileupload.attacks.rce.jsp.ImageWithJSPSnippetFileUpload;
import org.sasanlabs.fileupload.attacks.rce.jsp.SimpleJSPFileUpload;
import org.sasanlabs.fileupload.attacks.rce.jsp.SimpleJSPXFileUpload;
import org.sasanlabs.fileupload.attacks.rce.php.ImageWithPHPSnippetFileUpload;
import org.sasanlabs.fileupload.attacks.rce.php.SimplePHPFileUpload;
import org.sasanlabs.fileupload.attacks.xss.HtmlFileUpload;
import org.sasanlabs.fileupload.attacks.xss.SVGFileUpload;
import org.sasanlabs.fileupload.configuration.FileUploadConfiguration;
import org.sasanlabs.fileupload.exception.FileUploadException;

/**
 * {@code FileUploadAttackExecutor} class is used to find File Upload vulnerability by executing
 * list of {@code AttackVector}.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class FileUploadAttackExecutor {

    private HttpMessage originalHttpMessage;
    private FileUploadScanRule fileUploadScanRule;
    private List<NameValuePair> nameValuePairs = new ArrayList<>();
    private String originalFileName;
    private String originalContentType;
    private List<AttackVector> attackVectors =
            Arrays.asList(
                    new HtmlFileUpload(),
                    new SVGFileUpload(),
                    new SimpleJSPFileUpload(),
                    new SimpleJSPXFileUpload(),
                    new ImageWithJSPSnippetFileUpload(),
                    new HTAccessFileUpload(),
                    new SimplePHPFileUpload(),
                    new ImageWithPHPSnippetFileUpload(),
                    new EicarAntivirusTestFileUpload());

    public FileUploadAttackExecutor(
            FileUploadScanRule fileUploadScanRule,
            List<NameValuePair> nameValuePairs,
            String originalFileName,
            String originalContentType) {
        super();
        this.originalHttpMessage = fileUploadScanRule.getBaseMsg();
        this.fileUploadScanRule = fileUploadScanRule;
        this.nameValuePairs.addAll(nameValuePairs);
        this.originalFileName = originalFileName;
        this.originalContentType = originalContentType;
    }

    public boolean executeAttack() throws FileUploadException {

        Boolean shouldSendRequestsAfterFindingVulnerability =
                FileUploadConfiguration.getInstance().getSendRequestsAfterFindingVulnerability();

        for (AttackVector attackVector : attackVectors) {
            if (this.fileUploadScanRule.isStop()) {
                return false;
            } else {
                if (attackVector.execute(this) && !shouldSendRequestsAfterFindingVulnerability) {
                    return true;
                }
            }
        }
        return false;
    }

    public HttpMessage getOriginalHttpMessage() {
        return originalHttpMessage.cloneAll();
    }

    public FileUploadScanRule getFileUploadScanRule() {
        return fileUploadScanRule;
    }

    public List<NameValuePair> getNameValuePairs() {
        return Collections.unmodifiableList(nameValuePairs);
    }

    public String getOriginalFileName() {
        return originalFileName;
    }

    public String getOriginalContentType() {
        return originalContentType;
    }
}
