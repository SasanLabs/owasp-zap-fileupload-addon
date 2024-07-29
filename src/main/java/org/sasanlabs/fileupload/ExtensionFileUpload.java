/**
 * Copyright 2024 SasanLabs
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

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.sasanlabs.fileupload.configuration.FileUploadConfiguration;
import org.sasanlabs.fileupload.i18n.FileUploadI18n;
import org.sasanlabs.fileupload.ui.FileUploadOptionsPanel;

/**
 * @author KSASAN preetkaran20@gmail.com
 * @since 1.0.0
 */
public class ExtensionFileUpload extends ExtensionAdaptor {

    protected static final Logger LOGGER = LogManager.getLogger(ExtensionFileUpload.class);

    static {
        FileUploadI18n.init();
    }

    @Override
    public String getAuthor() {
        return "KSASAN preetkaran20@gmail.com";
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(new FileUploadOptionsPanel());
        }
        extensionHook.addOptionsParamSet(FileUploadConfiguration.getInstance());
        LOGGER.debug("FileUpload Extension loaded successfully");
    }

    @Override
    public void unload() {
        super.unload();
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
