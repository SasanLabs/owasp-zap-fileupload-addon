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
package org.sasanlabs.fileupload.attacks.rce;

/** @author KSASAN preetkaran20@gmail.com */
public class PathTraversal /*implements AttackVector*/ {
    //
    //	private static final String XSS_UPLOADED_FILE_BASE_NAME = "XSSByHtmlUpload_";
    //	private static final String XSS_PAYLOAD_HTML_FILE = "<html><head></head><body>Testing
    // XSS</body></html>";
    //
    //	private static final List<String> HTML_EXTENSIONS = Arrays.asList("htm", "html", "xhtml");
    //	private static final List<String> CONTENT_TYPES =
    // Arrays.asList(Constants.EMPTY_STRING,"text/html", "text/plain");
    //
    //	private static final ContentMatcher CONTENT_MATCHER = new MD5HashResponseMatcher();
    //
    //	@Override
    //	public boolean execute(FileUploadAttackExecutor fileUploadAttackExecutor) throws
    // FileUploadException {
    //		// TODO Auto-generated method stub
    //		return false;
    //	}

    //	private boolean isContentDispositionInline(HttpMessage preflightMsg) {
    //		String headerValue = preflightMsg.getResponseHeader().getHeader("Content-Disposition");
    //		if (headerValue == null || headerValue.trim().equals(Constants.EMPTY_STRING) ||
    // headerValue.equals("inline")) {
    //			return true;
    //		}
    //		return false;
    //	}

    /**
     * Execute the experiment 1. change only content type 2. change only html or htm 3. change html
     * extension and text/plain 4. change htm extension and text/plain or text/html
     */
}
