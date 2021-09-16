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
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.configuration.FileUploadConfiguration;
import org.sasanlabs.fileupload.i18n.FileUploadI18n;
import org.zaproxy.zap.core.scanner.InputVector;
import org.zaproxy.zap.core.scanner.InputVectorBuilder;

/**
 * {@code FileUploadScanRule} is used to find the vulnerabilities in File Upload functionality of
 * applications. The scan rule uploads multiple types of files containing vulnerable code to check
 * if the application is vulnerable.
 *
 * <p>This addon fires a lot of requests to the target application hence can impact the performance
 * of the targeted application. So please run this addon in non-prod environment only.
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since 1.0.0
 */
public class FileUploadScanRule extends AbstractAppParamPlugin {

    private static final int PLUGIN_ID = 40041;
    private static final String NAME = FileUploadI18n.getMessage("fileupload.scanrule.name");
    private static final String DESCRIPTION =
            FileUploadI18n.getMessage("fileupload.scanrule.description");
    private static final String SOLUTION = FileUploadI18n.getMessage("fileupload.scanrule.soln");
    private static final String REFERENCE = FileUploadI18n.getMessage("fileupload.scanrule.refs");
    private static final Logger LOGGER = LogManager.getLogger(FileUploadScanRule.class);

    private int maxRequestCount;

    @Override
    public void init() {
        if (!this.isConfigured()) {
            getParent()
                    .pluginSkipped(
                            this,
                            FileUploadI18n.getMessage(
                                    "fileupload.configuration.not.present.skipping.scanrule"));
            return;
        }
        switch (this.getAttackStrength()) {
            case LOW:
                maxRequestCount = 75;
                break;
            case MEDIUM:
                maxRequestCount = 150;
                break;
            case HIGH:
                maxRequestCount = 250;
                break;
            case INSANE:
                maxRequestCount = 450;
                break;
            default:
                maxRequestCount = 150;
                break;
        }
    }

    @Override
    public boolean isStop() {
        return super.isStop() || (this.maxRequestCount <= 0);
    }

    public void decreaseRequestCount() {
        this.maxRequestCount--;
    }

    private boolean isConfigured() {
        return StringUtils.isNotBlank(
                        FileUploadConfiguration.getInstance().getStaticLocationURIRegex())
                || StringUtils.isNotBlank(
                        FileUploadConfiguration.getInstance().getDynamicLocationURIRegex())
                || (StringUtils.isNotBlank(
                                FileUploadConfiguration.getInstance()
                                        .getParseResponseStartIdentifier())
                        && StringUtils.isNotBlank(
                                FileUploadConfiguration.getInstance()
                                        .getParseResponseEndIdentifier()));
    }

    @Override
    protected void scan(List<NameValuePair> nameValuePairs) {
        try {
            boolean isMultipart = false;
            String originalFileName = null, originalContentType = null;
            if (nameValuePairs != null) {
                for (NameValuePair nameValuePair : nameValuePairs) {
                    if (nameValuePair.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME) {
                        originalFileName = nameValuePair.getValue();
                        isMultipart = true;
                    } else if (nameValuePair.getType()
                            == NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE) {
                        originalContentType = nameValuePair.getValue();
                        isMultipart = true;
                    } else if (nameValuePair.getType()
                            == NameValuePair.TYPE_MULTIPART_DATA_FILE_PARAM) {
                        isMultipart = true;
                    }
                }
            }
            if (isMultipart) {
                FileUploadAttackExecutor fileUploadAttackExecutor =
                        new FileUploadAttackExecutor(
                                this, nameValuePairs, originalFileName, originalContentType);
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

    @Override
    public void sendAndReceive(HttpMessage msg) throws IOException {
        super.sendAndReceive(msg);
    }

    @Override
    public HttpMessage getBaseMsg() {
        return super.getBaseMsg();
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
