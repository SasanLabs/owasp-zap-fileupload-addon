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
package org.sasanlabs.fileupload;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.core.scanner.VariantMultipartFormParameters;
import org.parosproxy.paros.network.HttpMessage;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;

/** @author KSASAN preetkaran20@gmail.com */
public class FileUploadScanRule extends AbstractAppVariantPlugin {

    private static final int PLUGIN_ID = 110009;
    private static final String NAME = "File Upload"; // JWTI18n.getMessage("jwt.scanner.name");
    private static final String DESCRIPTION =
            "File Upload"; // JWTI18n.getMessage("jwt.scanner.description");
    private static final String SOLUTION = "File Upload"; // JWTI18n.getMessage("jwt.scanner.soln");
    private static final String REFERENCE =
            "File Upload"; // JWTI18n.getMessage("jwt.scanner.refs");
    private static final Logger LOGGER = Logger.getLogger(FileUploadScanRule.class);
    private Variant variant = null;
    private static final Set<Integer> ALLOWED_TYPES =
            new HashSet<Integer>(
                    Arrays.asList(
                            NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE,
                                    NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME,
                            NameValuePair.TYPE_MULTIPART_DATA_FILE_PARAM,
                                    NameValuePair.TYPE_MULTIPART_DATA_PARAM));
    /*
     * Need to check what to include do we need to include XXE/XSS/Path Traversal in
     * this addon or we need to correct those. Persistent XXS/XXE/PathTraversal
     * might be different
     *
     * Will not include the reflected XSS because it should work and i have checked
     * it works.
     */

    // debug if all these types will be there in all Multipart requests
    // @Override
    public void scan(HttpMessage msg, Variant variant) {
        try {
            this.variant = variant;
            if (variant instanceof VariantMultipartFormParameters) {
                List<NameValuePair> nameValuePairs = variant.getParamList();
                nameValuePairs.forEach(
                        (nameValuePair) ->
                                LOGGER.error(
                                        nameValuePair.getName() + " " + nameValuePair.getValue()));
                FileUploadAttackExecutor fileUploadAttackExecutor =
                        new FileUploadAttackExecutor(msg, this, variant);
                fileUploadAttackExecutor.executeAttack();
            }
        } catch (Exception ex) {

        }
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
        this.sendAndReceive(msg);
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

    /**
     * Sets the parameter into the given {@code message}. If both parameter name and value are
     * {@code null}, the parameter will be removed.
     *
     * @param message the message that will be changed
     * @param originalPair original name value pair
     * @param param the name of the parameter
     * @param value the value of the parameter
     * @return the parameter set
     * @see #setEscapedParameter(HttpMessage, NameValuePair, String, String)
     */
    public String setParameter(
            HttpMessage message, NameValuePair originalPair, String param, String value) {
        return variant.setParameter(message, originalPair, param, value);
    }

    /**
     * Sets the parameter into the given {@code message}. If both parameter name and value are
     * {@code null}, the parameter will be removed.
     *
     * <p>The value is expected to be properly encoded/escaped.
     *
     * @param message the message that will be changed
     * @param originalPair original name value pair
     * @param param the name of the parameter
     * @param value the value of the parameter
     * @return the parameter set
     * @see #setParameter(HttpMessage,NameValuePair, String, String)
     */
    public String setEscapedParameter(
            HttpMessage message, NameValuePair originalPair, String param, String value) {
        return variant.setEscapedParameter(message, originalPair, param, value);
    }
}
