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

import java.util.function.Function;

/**
 * @author KSASAN preetkaran20@gmail.com
 */
public class SimpleFileInformationProvider implements FileInformationProvider {

    private Function<String, String> fileNameFunction;
    private Function<String, String> contentTypeFunction;

    public SimpleFileInformationProvider(
            Function<String, String> fileNameFunction,
            Function<String, String> contentTypeFunction) {
        this.fileNameFunction = fileNameFunction;
        this.contentTypeFunction = contentTypeFunction;
    }

    @Override
    public String getFileName(String originalFileName) {
        return this.fileNameFunction.apply(originalFileName);
    }

    @Override
    public String getContentType(String originalContentType) {
        return this.contentTypeFunction.apply(originalContentType);
    }
    ;
}
