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

import java.util.Objects;

/**
 * {@code FileInformationProviderBuilder} is used to build the complex {@code
 * FileInformationProvider} object.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class FileInformationProviderBuilder {
    private FileInformationProviderImpl fileInformationProviderImpl;

    public FileInformationProviderBuilder(String baseFileName) {
        Objects.requireNonNull(baseFileName, "FileName cannot be null");
        fileInformationProviderImpl = new FileInformationProviderImpl(baseFileName);
    }

    public FileInformationProviderBuilder withFileExtensionOperation(
            FileExtensionOperation fileExtensionOperation) {
        fileInformationProviderImpl.setFileExtensionOperation(fileExtensionOperation);
        return this;
    }

    public FileInformationProviderBuilder withExtension(String providedExtension) {
        fileInformationProviderImpl.setExtension(providedExtension);
        return this;
    }

    public FileInformationProviderBuilder withContentType(String contentType) {
        fileInformationProviderImpl.setContentType(contentType);
        return this;
    }

    public FileInformationProvider build() {
        if ((fileInformationProviderImpl
                                .getFileExtensionOperation()
                                .equals(FileExtensionOperation.NO_EXTENSION)
                        || fileInformationProviderImpl
                                .getFileExtensionOperation()
                                .equals(FileExtensionOperation.ONLY_ORIGINAL_EXTENSION))
                && fileInformationProviderImpl.getExtension() != null) {
            throw new RuntimeException(
                    "Invalid combination, For FileExtensionOperation: "
                            + this.fileInformationProviderImpl.getFileExtensionOperation()
                            + ", ProvidedExtension should be null");
        }

        return fileInformationProviderImpl;
    }
}
