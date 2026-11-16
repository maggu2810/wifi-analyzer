// SPDX-License-Identifier: MIT
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// App version (SemVer): set by tools/android_release.py at a release (even minor) and at the
// start of the next development round (odd minor), see AGENTS.md "Versioning".
val appVersion = "0.3.0"

// Build identity from git (docs/decisions/0008-versioning-from-git.md): versionName is
// "0.2.1" at tag android-v0.2.1, otherwise e.g. "0.3.0-dev.4+g1a2b3c4[.dirty]";
// versionCode is the commit count (strictly increasing on main).
val gitVersionTool = rootDir.resolve("../../tools/git_version.py").path
val gitVersionName = providers.exec {
    commandLine("python3", gitVersionTool, "--prefix", "android-v", "--version", appVersion)
}.standardOutput.asText.map { it.trim() }
val gitVersionCode = providers.exec {
    commandLine("python3", gitVersionTool, "--count")
}.standardOutput.asText.map { it.trim().toInt() }

android {
    namespace = "de.maggu2810.android.wifianalyzer"
    compileSdk = 37
    // Same NDK as :wifi-analyze-native; also used to strip native libraries in release builds.
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "de.maggu2810.android.wifianalyzer"
        minSdk = 30
        targetSdk = 37
        versionCode = gitVersionCode.get()
        versionName = gitVersionName.get()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            // Must match the ABIs of :wifi-analyze-native.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    // Release signing from environment variables (set by the GitHub workflow from repository
    // secrets, see docs/decisions/0007-github-apk-distribution.md). Without them the release
    // APK stays unsigned (app-release-unsigned.apk), so local builds need no key.
    val releaseKeystore = System.getenv("ANDROID_KEYSTORE_FILE")?.takeIf { it.isNotBlank() }
    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storeType = "PKCS12"
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                // PKCS12: key password = store password.
                keyPassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            if (releaseKeystore != null) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    androidResources {
        // Per-app language support (Android 13+); locales from res/values-*.
        generateLocaleConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("test").resources.directories.add("../../../testdata")
    }
}

dependencies {
    implementation(project(":wifi-analyze-native"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.kotlinx.serialization.json)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    debugImplementation(libs.compose.ui.tooling)

    testImplementation(libs.junit)

    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.compose.ui.test.junit4)
    debugImplementation(libs.compose.ui.test.manifest)
}
