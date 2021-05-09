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
package org.sasanlabs.fileupload.attacks.antivirus;

import static org.sasanlabs.fileupload.FileUploadUtils.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.sasanlabs.fileupload.attacks.AttackVector;
import org.sasanlabs.fileupload.attacks.FileUploadAttackExecutor;
import org.sasanlabs.fileupload.attacks.beans.FileExtensionOperation;
import org.sasanlabs.fileupload.attacks.beans.FileParameter;
import org.sasanlabs.fileupload.attacks.beans.FileParameterBuilder;
import org.sasanlabs.fileupload.attacks.beans.VulnerabilityType;
import org.sasanlabs.fileupload.exception.FileUploadException;
import org.sasanlabs.fileupload.matcher.ContentMatcher;
import org.sasanlabs.fileupload.matcher.impl.MD5HashResponseMatcher;

/**
 * {@code EicarAntivirusTestFileUpload} attack vector is used to check the if antivirus is present
 * and working properly by uploading the Eicar test file. General idea is to upload the Eicar Test
 * file and if we are able to download it again then that means there are chances that Antivirus is
 * either not present or not working properly.
 *
 * <p>For more information about Eicar file please visit <a
 * href="https://en.wikipedia.org/wiki/EICAR_test_file">Eicar File Wiki link</a>
 *
 * <p>Tested Eicar test file on {@link https://www.virustotal.com/} 63 out of 67 AV softwares detect
 * it as a virus.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class EicarAntivirusTestFileUpload implements AttackVector {

    private static final String EICAR_FILE_CONTENT =
            new String(
                    Base64.getDecoder()
                            .decode(
                                    "WDVPIVAlQEFQWzRcUFpYNTQ"
                                            + "oUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVEl"
                                            + "WSVJVUy1URVNULUZJTEUhJEgrSCo="),
                    StandardCharsets.UTF_8);
    private static final String UPLOADED_BASE_FILE_NAME = "EicarAntivirusTestFileUpload_";

    private static final ContentMatcher CONTENT_MATCHER =
            new MD5HashResponseMatcher(EICAR_FILE_CONTENT);

    private static final List<FileParameter> FILE_PARAMETERS_DEFAULT =
            Arrays.asList(
                    /**
                     * Tested that the file content only matters in case of Eicar file and any
                     * extension with the same content will be flagged as a Virus file. Tested this
                     * hypothesis with {@link https://github.com/malice-plugins/mcafee} as well as
                     * on {@link https://www.virustotal.com/} Out of 67 antivirus softwares 63
                     * detect the Eicar file as virus file.
                     */
                    new FileParameterBuilder()
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_ORIGINAL_EXTENSION)
                            .build(),

                    // new FileParameter(FileExtensionOperation.ONLY_ORIGINAL_EXTENSION),
                    // Below file parameters might not be needed but just for a safe side added
                    // those.
                    new FileParameterBuilder()
                            .withBaseFileName(UPLOADED_BASE_FILE_NAME)
                            .withExtension("com")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(UPLOADED_BASE_FILE_NAME)
                            .withExtension("exe")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(UPLOADED_BASE_FILE_NAME)
                            .withExtension("com")
                            .withContentType("application/octet-stream")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(UPLOADED_BASE_FILE_NAME)
                            .withExtension("exe")
                            .withContentType("vnd.microsoft.portable-executable")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.ONLY_PROVIDED_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(UPLOADED_BASE_FILE_NAME)
                            .withExtension("com")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(UPLOADED_BASE_FILE_NAME)
                            .withExtension("exe")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(UPLOADED_BASE_FILE_NAME)
                            .withExtension("com")
                            .withContentType("application/octet-stream")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(UPLOADED_BASE_FILE_NAME)
                            .withExtension("exe")
                            .withContentType("vnd.microsoft.portable-executable")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.PREFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(UPLOADED_BASE_FILE_NAME)
                            .withExtension("com" + NULL_BYTE_CHARACTER)
                            .withContentType("application/octet-stream")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build(),
                    new FileParameterBuilder()
                            .withBaseFileName(UPLOADED_BASE_FILE_NAME)
                            .withExtension("exe" + NULL_BYTE_CHARACTER)
                            .withContentType("vnd.microsoft.portable-executable")
                            .withFileExtensionOperation(
                                    FileExtensionOperation.SUFFIX_ORIGINAL_EXTENSION)
                            .build());

    @Override
    public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor)
            throws FileUploadException {
        try {
            return this.genericAttackExecutor(
                    fileUploadAttackExecutor,
                    CONTENT_MATCHER,
                    EICAR_FILE_CONTENT,
                    FILE_PARAMETERS_DEFAULT,
                    VulnerabilityType.EICAR_FILE);
        } catch (IOException e) {
            throw new FileUploadException(e);
        }
    }
}
