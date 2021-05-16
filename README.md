# owasp-zap-fileupload-addon 
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) ![Java CI with Gradle](https://github.com/SasanLabs/owasp-zap-jwt-addon/workflows/Java%20CI%20with%20Gradle/badge.svg?branch=master)

This project contains the File Upload scan rule which is used to find the vulnerabilities in File Upload functionality.

## Why this addon is needed
File upload is becoming a more and more essential part of any application, where the user is able to upload their photo, their CV, or a video showcasing a project they are working on. The application should be able to fend off bogus and malicious files in a way to keep the application and the users safe. Generally file upload functionality is quite complex to automate and has huge attack surface  hence there is a need to automate the process and also secure it.

## Configuration
File upload functionality generally has 2 endpoints, one from where file is uploaded and one from where file is retrieved. It neccessary to know both these endpoints. While Active Scanning the application, file upload endpoint is already known but retrieval endpoint is not known to the scan rule hence there are configuration details specific to the retrieval endpoint.

Under ZAP's Options dialog you will find a JWT section as shown below:
![File Upload Options Panel](./docs/images/fileupload-options-panel.png)

### Explanation
For finding the url to retrieve the uploaded file, following are the options:
1. In some applications the url to retrieve the uploaded file is static and doesn't change or only the file name is changed. For handling this type of configuration, options panel has `Static Location Configuration` where static url is added into `URI Regex` field. `URI Regex` field also supports the dynamic file name by `${fileName}`
parameter, for e.g. `http://<baseurl>/${fileName}`
2. In some applications the url to retrieve the uploaded file is present in the file upload request's response. For handling this type of configuration, options panel has `Dynamic Location Configuration` which has 2 `Start Identifer` and `End Identifier`. These identifiers are used to locate the Url in the response.
3. In some applications the url to retrieve the uploaded file is present in the response of a different url which is called preflight request. E.g. Profile picture url is part of profile page and hence we need to parse the response of the profile page to find the url of the profile picture. For handling this type of configuration, options panel has `Dynamic Location Configuration` which has a `URI Regex`, `Start Identifier` and `End Identifier`. So File upload addon will invoke the Uri mentioned in `URI Regex` and then part the response using `Start Identifier` and `End Identifier`.	`URI Regex` field also supports the dynamic file name by `${fileName}`

## Contributing guidelines
Contributing guidelines are same as [ZAP](https://github.com/zaproxy/zaproxy).

## Contact Us
For any Queries/Bugs or Enhancement please raise an issue in this repository or [ZAP](https://github.com/zaproxy/zaproxy).
For any other kind of issues please send an email to karan.sasan@owasp.org