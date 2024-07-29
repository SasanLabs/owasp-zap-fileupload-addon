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
package org.sasanlabs.fileupload.attacks.model;

import org.sasanlabs.fileupload.exception.FileUploadException;

/**
 * {@code FileInformationProvider} interface is used to represent the new file properties.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
@FunctionalInterface
public interface FileInformationProvider {

    /**
     * Represents the content type of the file.
     *
     * @param originalContentType
     * @return content type
     */
    default String getContentType(String originalContentType) {
        return originalContentType;
    }
    ;

    /**
     * Represents the file name.
     *
     * @param originalFileName
     * @return file name
     * @throws FileUploadException
     */
    String getFileName(String originalFileName) throws FileUploadException;
}
