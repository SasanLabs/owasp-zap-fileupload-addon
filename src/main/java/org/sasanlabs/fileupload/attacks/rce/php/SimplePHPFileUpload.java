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
package org.sasanlabs.fileupload.attacks.rce.php;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.sasanlabs.fileupload.FileUploadUtils;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.model.FileExtensionOperation;
import org.sasanlabs.fileupload.attacks.model.FileInformationProvider;
import org.sasanlabs.fileupload.attacks.model.FileInformationProviderBuilder;
import org.sasanlabs.fileupload.attacks.model.VulnerabilityType;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.ContainsExpectedValueMatcher;

/**
 * Important links for learning about PHP File Upload: 1.
 * https://www.acunetix.com/websitesecurity/upload-forms-threat/ 2.
 * https://github.com/SasanLabs/VulnerableApp-php/blob/main/src/FileUploadVulnerability/FileUpload.php
 *
 * <p>This entire scan rule is tested against {@link https://github.com/SasanLabs/VulnerableApp-php}
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class SimplePHPFileUpload extends AttackVector {

    private static final String PHP_UPLOADED_FILE_BASE_NAME = "SimplePHPFileUpload_";
    private static final String PHP_FILE_EXTENSION = "php";
    static final List<String> PHP_VARIANT_EXTENSIONS_DEFAULT =
            Arrays.asList(PHP_FILE_EXTENSION, "php3", "php5", "phtml");
    static final List<String> PHP_VARIANT_EXTENSIONS_EXTENDED =
            Arrays.asList("Php", "PHP", "Php3", "PHP3", "Php5", "PHP5", "Phtml", "PHTML");
    private static final String PHP_PAYLOAD =
            "<?php echo \"SimplePHPFileUpload\".\"_SasanLabs_ZAP_Identifier\" ?>";

    private static final ContentMatcher CONTENT_MATCHER =
            new ContainsExpectedValueMatcher("SimplePHPFileUpload_SasanLabs_ZAP_Identifier");

    private static List<FileInformationProvider> getDefaultFileParameters() {
        List<FileInformationProvider> fileInformationProviders = new ArrayList<>();
        FileUploadUtils.getFileInformationProvidersPHP(
                PHP_UPLOADED_FILE_BASE_NAME, PHP_VARIANT_EXTENSIONS_DEFAULT);
        fileInformationProviders.add(
                new FileInformationProviderBuilder(PHP_UPLOADED_FILE_BASE_NAME)
                        .withExtension(PHP_FILE_EXTENSION + FileUploadUtils.NULL_BYTE_CHARACTER)
                        .withFileExtensionOperation(
                                FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                        .build());
        fileInformationProviders.add(
                new FileInformationProviderBuilder(PHP_UPLOADED_FILE_BASE_NAME)
                        .withExtension(PHP_FILE_EXTENSION + FileUploadUtils.NULL_BYTE_CHARACTER)
                        .withContentType("application/x-httpd-php")
                        .withFileExtensionOperation(
                                FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                        .build());
        fileInformationProviders.add(
                new FileInformationProviderBuilder(PHP_UPLOADED_FILE_BASE_NAME)
                        .withExtension(PHP_FILE_EXTENSION + "%00")
                        .withFileExtensionOperation(
                                FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                        .build());
        fileInformationProviders.add(
                new FileInformationProviderBuilder(PHP_UPLOADED_FILE_BASE_NAME)
                        .withExtension(PHP_FILE_EXTENSION + "%00")
                        .withContentType("application/x-httpd-php")
                        .withFileExtensionOperation(
                                FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                        .build());
        return fileInformationProviders;
    }

    static final List<FileInformationProvider> FILE_PARAMETERS_DEFAULT = getDefaultFileParameters();
    static final List<FileInformationProvider> FILE_PARAMETERS_EXTENDED =
            FileUploadUtils.getFileInformationProvidersPHP(
                    PHP_UPLOADED_FILE_BASE_NAME, PHP_VARIANT_EXTENSIONS_EXTENDED);

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        boolean result =
                this.genericAttackExecutor(
                        fileUploadAttackExecutor,
                        PHP_PAYLOAD,
                        FILE_PARAMETERS_DEFAULT,
                        CONTENT_MATCHER,
                        VulnerabilityType.RCE_PHP_FILE);
        if (!result
                && fileUploadAttackExecutor
                        .getFileUploadScanRule()
                        .getAttackStrength()
                        .equals(AttackStrength.INSANE)) {
            result =
                    this.genericAttackExecutor(
                            fileUploadAttackExecutor,
                            PHP_PAYLOAD,
                            FILE_PARAMETERS_EXTENDED,
                            CONTENT_MATCHER,
                            VulnerabilityType.RCE_PHP_FILE);
        }

        return result;
    }
}
