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
package org.sasanlabs.fileupload.configuration;

import org.apache.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;

/**
 * This class holds configuration related to FileUpload Addon.
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since 1.0.0
 */
public class FileUploadConfiguration extends VersionedAbstractParam {

    protected static final Logger LOGGER = Logger.getLogger(FileUploadConfiguration.class);

    /** The base configuration key for all fileupload configurations. */
    private static final String PARAM_BASE_KEY = "fileupload";

    private static final String CONFIG_VERSION_KEY = PARAM_BASE_KEY + VERSION_ATTRIBUTE;
    private static final int CURRENT_CONFIG_VERSION = 1;
    private static final String PARAM_STATIC_LOCATION_CONFIGURATION_URI_REGEX =
            PARAM_BASE_KEY + ".staticlocation.uriregex";
    private static final String PARAM_DYNAMIC_LOCATION_CONFIGURATION_URI_REGEX =
            PARAM_BASE_KEY + ".dynamiclocation.uriregex";
    private static final String PARAM_DYNAMIC_LOCATION_CONFIGURATION_START_IDENTIFIER =
            PARAM_BASE_KEY + ".dynamiclocation.startidentifier";
    private static final String PARAM_DYNAMIC_LOCATION_CONFIGURATION_END_IDENTIFIER =
            PARAM_BASE_KEY + ".dynamiclocation.endidentifier";

    private String staticLocationURIRegex;
    private String dynamicLocationURIRegex;
    private String dynamicLocationStartIdentifier;
    private String dynamicLocationEndIdentifier;

    private static volatile FileUploadConfiguration fileUploadConfiguration;

    private FileUploadConfiguration() {}

    public static FileUploadConfiguration getInstance() {
        if (fileUploadConfiguration == null) {
            synchronized (FileUploadConfiguration.class) {
                if (fileUploadConfiguration == null) {
                    fileUploadConfiguration = new FileUploadConfiguration();
                }
            }
        }
        return fileUploadConfiguration;
    }

    public String getStaticLocationURIRegex() {
        return staticLocationURIRegex;
    }

    public void setStaticLocationURIRegex(String staticLocationURIRegex) {
        this.staticLocationURIRegex = staticLocationURIRegex;
        this.getConfig()
                .setProperty(PARAM_STATIC_LOCATION_CONFIGURATION_URI_REGEX, staticLocationURIRegex);
    }

    public String getDynamicLocationURIRegex() {
        return dynamicLocationURIRegex;
    }

    public void setDynamicLocationURIRegex(String dynamicLocationURIRegex) {
        this.dynamicLocationURIRegex = dynamicLocationURIRegex;
        this.getConfig()
                .setProperty(
                        PARAM_DYNAMIC_LOCATION_CONFIGURATION_URI_REGEX, dynamicLocationURIRegex);
    }

    public String getDynamicLocationStartIdentifier() {
        return dynamicLocationStartIdentifier;
    }

    public void setDynamicLocationStartIdentifier(String dynamicLocationStartIdentifier) {
        this.dynamicLocationStartIdentifier = dynamicLocationStartIdentifier;
        this.getConfig()
                .setProperty(
                        PARAM_DYNAMIC_LOCATION_CONFIGURATION_START_IDENTIFIER,
                        dynamicLocationStartIdentifier);
    }

    public String getDynamicLocationEndIdentifier() {
        return dynamicLocationEndIdentifier;
    }

    public void setDynamicLocationEndIdentifier(String dynamicLocationEndIdentifier) {
        this.dynamicLocationEndIdentifier = dynamicLocationEndIdentifier;
        this.getConfig()
                .setProperty(
                        PARAM_DYNAMIC_LOCATION_CONFIGURATION_END_IDENTIFIER,
                        dynamicLocationEndIdentifier);
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void parseImpl() {
        this.setStaticLocationURIRegex(
                getConfig().getString(PARAM_STATIC_LOCATION_CONFIGURATION_URI_REGEX));
        this.setDynamicLocationURIRegex(
                getConfig().getString(PARAM_DYNAMIC_LOCATION_CONFIGURATION_URI_REGEX));
        this.setDynamicLocationStartIdentifier(
                getConfig().getString(PARAM_DYNAMIC_LOCATION_CONFIGURATION_START_IDENTIFIER));
        this.setDynamicLocationEndIdentifier(
                getConfig().getString(PARAM_DYNAMIC_LOCATION_CONFIGURATION_END_IDENTIFIER));
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}
}
