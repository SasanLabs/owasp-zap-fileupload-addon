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
package org.sasanlabs.fileupload.attacks.beans;

import java.util.Objects;

/**
 * {@code FileParameterBuilder} is used to build the complex {@code FileParameter} object.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class FileParameterBuilder {
    private FileParameterImpl fileParameterImpl;

    public FileParameterBuilder() {}

    public FileParameterBuilder withFileNameAsOriginalExtension() {
        fileParameterImpl = new FileParameterImpl();
        return this;
    }

    public FileParameterBuilder withFileName(String fileName) {
        Objects.requireNonNull(fileName, "BaseFileName cannot be null");
        fileParameterImpl = new FileParameterImpl(fileName, false);
        return this;
    }

    public FileParameterBuilder withBaseFileName(String baseFileName) {
        Objects.requireNonNull(baseFileName, "BaseFileName cannot be null");
        fileParameterImpl = new FileParameterImpl(baseFileName);
        return this;
    }

    public FileParameterBuilder withFileExtensionOperation(
            FileExtensionOperation fileExtensionOperation) {
        fileParameterImpl.setFileExtensionOperation(fileExtensionOperation);
        return this;
    }

    public FileParameterBuilder withExtension(String providedExtension) {
        fileParameterImpl.setExtension(providedExtension);
        return this;
    }

    public FileParameterBuilder withContentType(String contentType) {
        fileParameterImpl.setContentType(contentType);
        return this;
    }

    public FileParameter build() {
        if ((fileParameterImpl
                                .getFileExtensionOperation()
                                .equals(FileExtensionOperation.NO_EXTENSION)
                        || fileParameterImpl
                                .getFileExtensionOperation()
                                .equals(FileExtensionOperation.ONLY_ORIGINAL_EXTENSION))
                && fileParameterImpl.getExtension() != null) {
            throw new RuntimeException(
                    "Invalid combination, For FileExtensionOperation: "
                            + this.fileParameterImpl.getFileExtensionOperation()
                            + " and ProvidedExtension should be null");
        }
        return fileParameterImpl;
    }
}
