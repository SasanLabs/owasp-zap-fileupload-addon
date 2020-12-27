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
package org.sasanlabs.fileupload;

import org.parosproxy.paros.network.HttpMessage;

/**
 * Contains the String constants or other utility constants used by the File Upload Addon.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public interface Constants {
    String EMPTY_STRING = "";
    String PERIOD = ".";
    String SLASH = "/";
    String NULL_BYTE_CHARACTER = String.valueOf((char) 0);
    String HTTP_SCHEME = "http://";
    String HTTP_SECURED_SCHEME = "https://";

    static boolean isContentDispositionInline(HttpMessage preflightMsg) {
        String headerValue = preflightMsg.getResponseHeader().getHeader("Content-Disposition");
        if (headerValue == null
                || headerValue.trim().equals(Constants.EMPTY_STRING)
                || headerValue.equals("inline")) {
            return true;
        }
        return false;
    }
}
