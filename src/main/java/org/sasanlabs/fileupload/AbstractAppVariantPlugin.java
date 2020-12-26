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

import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
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
            scan(msg, variant);
        } catch (Exception e) {
            logger.error("Error occurred while scanning a message:", e);
        }
    }

    /**
     * Plugin method that need to be implemented for the specific test. The passed message is a copy
     * which maintains only the Request's information so if the plugin need to manage the original
     * Response body a getBaseMsg() call should be done. the param name and the value are the
     * original value retrieved by the crawler and the current applied Variant.
     *
     * @param msg a copy of the HTTP message currently under scanning
     * @param variant
     */
    public abstract void scan(HttpMessage msg, Variant variant);
}
