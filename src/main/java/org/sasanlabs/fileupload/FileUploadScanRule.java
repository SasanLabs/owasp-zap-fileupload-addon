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
package org.sasanlabs.fileupload;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.i18n.FileUploadI18n;
import org.zaproxy.zap.core.scanner.InputVector;
import org.zaproxy.zap.core.scanner.InputVectorBuilder;

/**
 * {@code FileUploadScanRule} is used to find the vulnerabilities in File Upload functionality of
 * applications. The scan rule uploads multiple types of files containing vulnerable code to check
 * if the application is vulnerable.
 *
 * <p>This addon fires a lot of requests to the target application hence can impacts the performance
 * of the targeted application. So please run this addon in non-prod environment only.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class FileUploadScanRule extends AbstractAppParamPlugin {

    private static final int PLUGIN_ID = 110009;
    private static final String NAME = FileUploadI18n.getMessage("fileupload.scanrule.name");
    private static final String DESCRIPTION =
            FileUploadI18n.getMessage("fileupload.scanrule.description");
    private static final String SOLUTION = FileUploadI18n.getMessage("fileupload.scanrule.soln");
    private static final String REFERENCE = FileUploadI18n.getMessage("fileupload.scanrule.refs");
    private static final Logger LOGGER = LogManager.getLogger(FileUploadScanRule.class);

    private AtomicInteger maxRequestCount;

    @Override
    public void init() {
        switch (this.getAttackStrength()) {
            case LOW:
                maxRequestCount = new AtomicInteger(30);
                break;
            case MEDIUM:
                maxRequestCount = new AtomicInteger(60);
                break;
            case HIGH:
                maxRequestCount = new AtomicInteger(90);
                break;
            case INSANE:
                maxRequestCount = new AtomicInteger(150);
                break;
            default:
                maxRequestCount = new AtomicInteger(60);
                break;
        }
    }

    @Override
    public boolean isStop() {
        return super.isStop() || (this.maxRequestCount.get() <= 0);
    }

    public void decreaseRequestCount() {
        this.maxRequestCount.getAndDecrement();
    }

    @Override
    protected void scan(HttpMessage msg, List<NameValuePair> nameValuePairs) {
        try {
            boolean isMultipart = false;
            if (nameValuePairs != null) {
                isMultipart =
                        nameValuePairs.stream()
                                .anyMatch(
                                        nameValuePair ->
                                                nameValuePair.getType()
                                                                == NameValuePair
                                                                        .TYPE_MULTIPART_DATA_FILE_NAME
                                                        || nameValuePair.getType()
                                                                == NameValuePair
                                                                        .TYPE_MULTIPART_DATA_FILE_PARAM
                                                        || nameValuePair.getType()
                                                                == NameValuePair
                                                                        .TYPE_MULTIPART_DATA_FILE_CONTENTTYPE);
            }
            if (isMultipart) {
                nameValuePairs.forEach(
                        (nameValuePair) ->
                                LOGGER.error(
                                        nameValuePair.getName() + " " + nameValuePair.getValue()));
                FileUploadAttackExecutor fileUploadAttackExecutor =
                        new FileUploadAttackExecutor(msg, this, nameValuePairs);
                fileUploadAttackExecutor.executeAttack();
            }
        } catch (Exception ex) {
            LOGGER.error("Error occurred while scanning", ex);
        }
    }

    @Override
    public InputVectorBuilder getBuilder() {
        return super.getBuilder();
    }

    @Override
    public void setParameters(HttpMessage message, List<InputVector> inputVectors) {
        super.setParameters(message, inputVectors);
    }

    public void raiseAlert(
            int risk,
            int confidence,
            String name,
            String description,
            String uri,
            String param,
            String attack,
            String otherInfo,
            String solution,
            HttpMessage msg) {
        newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setName(name)
                .setDescription(description)
                .setUri(uri)
                .setParam(param)
                .setAttack(attack)
                .setOtherInfo(otherInfo)
                .setSolution(solution)
                .setMessage(msg)
                .raise();
    }

    public void sendAndRecieve(HttpMessage msg) throws IOException {
        super.sendAndReceive(msg);
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public String getSolution() {
        return SOLUTION;
    }

    @Override
    public String getReference() {
        return REFERENCE;
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }
}
