// SPDX-License-Identifier: MIT
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "de.maggu2810.android.wifianalyzer.nativelib"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    defaultConfig {
        minSdk = 30
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                arguments += listOf("-DWIFI_WARNINGS_AS_ERRORS=ON")
            }
        }
    }

    externalNativeBuild {
        cmake {
            // Compiles libs/wifi-analyze from source (no prebuilt artifacts).
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        // JVM unit tests read the golden JSON files of the C++ library.
        getByName("test").resources.directories.add("../../../testdata/golden")
    }
}

dependencies {
    api(libs.kotlinx.serialization.json)
    testImplementation(libs.junit)
}
