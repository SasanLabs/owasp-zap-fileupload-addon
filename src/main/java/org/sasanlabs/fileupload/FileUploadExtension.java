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

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ViewDelegate;
import org.sasanlabs.fileupload.configuration.FileUploadConfiguration;
import org.sasanlabs.fileupload.i18n.FileUploadI18n;
import org.sasanlabs.fileupload.ui.FileUploadOptionsPanel;

/**
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class FileUploadExtension extends ExtensionAdaptor {

    protected static final Logger LOGGER = Logger.getLogger(FileUploadExtension.class);

    @Override
    public String getAuthor() {
        return "KSASAN preetkaran20@gmail.com";
    }

    @Override
    public void init() {}

    @Override
    public void initView(ViewDelegate view) {
        super.initView(view);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        FileUploadI18n.init();
        super.hook(extensionHook);
        extensionHook.getHookView().addOptionPanel(new FileUploadOptionsPanel());
        LOGGER.debug("FileUpload Extension loaded successfully");
        extensionHook.addOptionsParamSet(FileUploadConfiguration.getInstance());
    }

    @Override
    public void unload() {
        super.unload();
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
