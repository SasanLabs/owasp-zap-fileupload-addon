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
package org.sasanlabs.fileupload.attacks.beans;

import org.apache.commons.lang3.StringUtils;
import org.sasanlabs.fileupload.Constants;
import org.sasanlabs.fileupload.attacks.FileUploadException;

/**
 * {@code FileExtensionOperation} is used to denote the operation on the file name extensions.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public enum FileExtensionOperation {

    /**
     * appends the Original File Extension before the provided extension. e.g. if provided extension
     * is {@code html} and original file extension is {@code pdf} then the final extension will be
     * {@code pdf.html}
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
    ONLY_PROVIDED_EXTENSION;

    public static String appendPeriodCharacter(String extension) {
        if (StringUtils.isBlank(extension)) {
            return extension;
        } else {
            if (extension.startsWith(Constants.PERIOD)) {
                return extension;
            }
            return Constants.PERIOD + extension;
        }
    }

    public String operator(String providedExtension, String originalFileName)
            throws FileUploadException {
        if (StringUtils.isBlank(providedExtension)) {
            throw new FileUploadException("Provided extension is null");
        }
        String extension;
        int firstIndexOfPeriodCharacter;
        String originalExtension = "";
        if (originalFileName != null) {
            firstIndexOfPeriodCharacter = originalFileName.indexOf(Constants.PERIOD);
            if (firstIndexOfPeriodCharacter >= 0) {
                originalExtension = originalFileName.substring(firstIndexOfPeriodCharacter + 1);
            }
        }
        switch (this) {
            case PREFIX_ORIGINAL_EXTENSION:
                extension = originalExtension + appendPeriodCharacter(providedExtension);
                break;
            case SUFFIX_ORIGINAL_EXTENSION:
                extension = providedExtension + appendPeriodCharacter(originalExtension);
                break;
            case ONLY_PROVIDED_EXTENSION:
                extension = providedExtension;
                break;
            default:
                extension = providedExtension;
        }
        return extension;
    }
}
