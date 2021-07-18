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
package org.sasanlabs.fileupload.attacks.model;

import org.apache.commons.lang3.StringUtils;
import org.sasanlabs.fileupload.FileUploadUtils;
import org.sasanlabs.fileupload.exception.FileUploadException;

/**
 * {@code FileExtensionOperation} is used to denote the operation on the file name extensions.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public enum FileExtensionOperation {

    /** don't append any extension to the filename. */
    NO_EXTENSION,

    /**
     * prefixes the Original File Extension before the provided extension. e.g. if provided
     * extension is {@code html} and original file extension is {@code pdf} then the final extension
     * will be {@code pdf.html}
     */
    PREFIX_ORIGINAL_EXTENSION,

    /**
     * appends the Original File Extension after the provided extension e.g. if provided extension
     * is {@code html%00} and original file extension is {@code pdf} then the final extension will
     * be {@code html%00.pdf}
     */
    SUFFIX_ORIGINAL_EXTENSION,

    /**
     * only appends the provided extension e.g. if provided extension is {@code html} and original
     * file extension is {@code pdf} then final extension will be {@code .html}
     */
    ONLY_PROVIDED_EXTENSION,

    /**
     * don't change the extension of original file and use the original extension. e.g. if provided
     * extension is {@code html} and original file extension is {@code pdf} then final extension
     * will be {@code .pdf}
     */
    ONLY_ORIGINAL_EXTENSION;

    public String operate(String providedExtension, String originalFileName)
            throws FileUploadException {
        if (StringUtils.isBlank(providedExtension)
                && !(this.equals(ONLY_ORIGINAL_EXTENSION) || this.equals(NO_EXTENSION))) {
            throw new FileUploadException(
                    "Provided extension cannot be null for FileExtensionOperation: " + this.name());
        }
        String extension;
        String originalExtension = "";
        if (originalFileName != null) {
            originalExtension = FileUploadUtils.getExtension(originalFileName);
        }
        switch (this) {
            case PREFIX_ORIGINAL_EXTENSION:
                extension =
                        FileUploadUtils.prefixExtensionWithPeriodCharacter(
                                originalExtension
                                        + FileUploadUtils.prefixExtensionWithPeriodCharacter(
                                                providedExtension));
                break;
            case SUFFIX_ORIGINAL_EXTENSION:
                extension =
                        FileUploadUtils.prefixExtensionWithPeriodCharacter(
                                providedExtension
                                        + FileUploadUtils.prefixExtensionWithPeriodCharacter(
                                                originalExtension));
                break;
            case ONLY_PROVIDED_EXTENSION:
                extension = FileUploadUtils.prefixExtensionWithPeriodCharacter(providedExtension);
                break;
            case ONLY_ORIGINAL_EXTENSION:
                extension = FileUploadUtils.prefixExtensionWithPeriodCharacter(originalExtension);
            case NO_EXTENSION:
                extension = "";
            default:
                extension = FileUploadUtils.prefixExtensionWithPeriodCharacter(providedExtension);
        }
        return extension;
    }
}
