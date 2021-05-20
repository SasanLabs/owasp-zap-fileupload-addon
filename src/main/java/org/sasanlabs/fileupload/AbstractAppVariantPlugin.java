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

import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascan.VariantFactory;

/**
 * {@code AbstractAppVariantPlugin} is the abstract base class which is used to run per variant to
 * modify multiple name value pairs of the {@code HttpMessage} per variant.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public abstract class AbstractAppVariantPlugin extends AbstractAppPlugin {

    private final Logger logger = Logger.getLogger(this.getClass());
    private Variant variant;

    @Override
    public void scan() {
        VariantFactory factory = Model.getSingleton().getVariantFactory();

        List<Variant> listVariant =
                factory.createVariants(this.getParent().getScannerParam(), this.getBaseMsg());

        if (listVariant.isEmpty()) {
            getParent()
                    .pluginSkipped(
                            this,
                            Constant.messages.getString(
                                    "ascan.progress.label.skipped.reason.noinputvectors"));
            return;
        }

        for (int i = 0; i < listVariant.size() && !isStop(); i++) {

            HttpMessage msg = getNewMsg();
            // ZAP: Removed unnecessary cast.
            Variant variant = listVariant.get(i);
            try {
                variant.setMessage(msg);
                scanVariant(variant);

            } catch (Exception e) {
                logger.error(
                        "Error occurred while scanning with variant "
                                + variant.getClass().getCanonicalName(),
                        e);
            }

            // ZAP: Implement pause and resume
            while (getParent().isPaused() && !isStop()) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
    }

    /** Scan the current message using the current Variant */
    private void scanVariant(Variant variant) {
        HttpMessage msg = getNewMsg();
        try {
            this.variant = variant;
            scan(msg, variant.getParamList());
        } catch (Exception e) {
            logger.error("Error occurred while scanning a message:", e);
        }
    }

    /**
     * Scan the current message using the provided Variant
     *
     * @param msg a copy of the HTTP message currently under scanning
     * @param nameValuePairs ParamList of a Variant
     */
    public abstract void scan(HttpMessage msg, List<NameValuePair> nameValuePairs);

    /**
     * Sets the parameter into the given {@code message}. If both parameter name and value are
     * {@code null}, the parameter will be removed.
     *
     * @param message the message that will be changed
     * @param nameValuePair of the message
     * @param param the name of the parameter
     * @param value the value of the parameter
     * @return the parameter set
     * @see #setEscapedParameter(HttpMessage, NameValuePair, String, String)
     */
    protected String setParameter(
            HttpMessage message, NameValuePair nameValuePair, String param, String value) {
        return variant.setParameter(message, nameValuePair, param, value);
    }

    /**
     * Sets the parameters into the given {@code message}. If both parameter name and value are
     * {@code null}, the parameter will be removed.
     *
     * <p>The value is expected to be properly encoded/escaped.
     *
     * @param message the message that will be changed
     * @param nameValuePairs of the message
     * @param params list of name of the parameter
     * @param values list of value of the parameter
     * @return the parameter set
     * @see #setParameters(HttpMessage, List, List, List)
     */
    protected String setEscapedParameters(
            HttpMessage message,
            List<NameValuePair> nameValuePairs,
            List<String> params,
            List<String> values) {
        return variant.setEscapedParameters(message, nameValuePairs, params, values);
    }

    /**
     * Sets the parameters into the given {@code message}. If both parameter name and value are
     * {@code null}, the parameter will be removed.
     *
     * @param message the message that will be changed
     * @param nameValuePairs of the message
     * @param params list of name of the parameter
     * @param values list of value of the parameter
     * @return the parameter set
     * @see #setEscapedParameters(HttpMessage, List, List, List)
     */
    protected String setParameters(
            HttpMessage message,
            List<NameValuePair> nameValuePairs,
            List<String> params,
            List<String> values) {
        return variant.setParameters(message, nameValuePairs, params, values);
    }

    /**
     * Sets the parameter into the given {@code message}. If both parameter name and value are
     * {@code null}, the parameter will be removed.
     *
     * <p>The value is expected to be properly encoded/escaped.
     *
     * @param message the message that will be changed
     * @param nameValuePair of the message
     * @param param the name of the parameter
     * @param value the value of the parameter
     * @return the parameter set
     * @see #setParameter(HttpMessage, NameValuePair, String, String)
     */
    protected String setEscapedParameter(
            HttpMessage message, NameValuePair nameValuePair, String param, String value) {
        return variant.setEscapedParameter(message, nameValuePair, param, value);
    }
}
