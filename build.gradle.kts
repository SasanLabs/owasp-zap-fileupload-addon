import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml
import org.zaproxy.gradle.addon.misc.CreateGitHubRelease
import org.zaproxy.gradle.addon.misc.ExtractLatestChangesFromChangelog

plugins {
    id("com.diffplug.gradle.spotless") version "3.27.2"
    id("com.github.ben-manes.versions") version "0.38.0"
    `java-library`
    id("org.zaproxy.add-on") version "0.5.0"
}

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

spotless {
    java {
        licenseHeaderFile("./gradle/spotless/License.java")
        googleJavaFormat().aosp()
    }
}

tasks.compileJava {
    dependsOn("spotlessApply")
}

tasks.withType<JavaCompile>().configureEach { options.encoding = "utf-8"}

version = "1.1.0"
description = "Detect File upload requests and scan them to find related vulnerabilities"

zapAddOn {
    addOnName.set("FileUpload")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.11.0")
    manifest {
        author.set("KSASAN preetkaran20@gmail.com")
        repo.set("https://github.com/SasanLabs/owasp-zap-fileupload-addon/")
    }
}

dependencies {
	zap("org.zaproxy:zap:2.11.0")
}
