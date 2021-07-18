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

import java.util.Date;
import java.util.Random;
import org.sasanlabs.fileupload.exception.FileUploadException;

/** @author KSASAN preetkaran20@gmail.com */
class FileParameterImpl implements FileParameter {

    private String baseFileName;
    private String extension;
    private String contentType;
    private FileExtensionOperation fileExtensionOperation = FileExtensionOperation.NO_EXTENSION;

    FileParameterImpl(String baseFileName) {
        this.baseFileName = baseFileName + (new Random(new Date().getTime()).nextLong());
    }

    void setExtension(String extension) {
        this.extension = extension;
    }

    void setContentType(String contentType) {
        this.contentType = contentType;
    }

    void setFileExtensionOperation(FileExtensionOperation fileExtensionOperation) {
        this.fileExtensionOperation = fileExtensionOperation;
    }

    String getExtension() {
        return extension;
    }

    FileExtensionOperation getFileExtensionOperation() {
        return fileExtensionOperation;
    }

    @Override
    public String getContentType(String originalContentType) {
        return contentType == null ? originalContentType : this.contentType;
    }

    @Override
    public String getFileName(String originalFileName) throws FileUploadException {
        if (originalFileName == null) {
            throw new FileUploadException("Provided original File Name is null");
        }

        return this.baseFileName + fileExtensionOperation.operate(this.extension, originalFileName);
    }
}
