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
package org.sasanlabs.fileupload.i18n;

import java.util.ResourceBundle;
import org.parosproxy.paros.Constant;

/**
 * Message Bundle
 *
 * @author KSASAN preetkaran20@gmail.com
 * @since 1.0.0
 */
public class FileUploadI18n {
    private static ResourceBundle message;

    public static void init() {
        message =
                ResourceBundle.getBundle(
                        FileUploadI18n.class.getPackage().getName() + ".Messages",
                        Constant.getLocale());
    }

    public static String getMessage(String key) {
        if (key != null && message != null && message.containsKey(key)) {
            return message.getString(key);
        }
        return "";
    }

    public static ResourceBundle getResourceBundle() {
        return message;
    }
}
