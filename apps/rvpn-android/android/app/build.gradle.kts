plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

fun workspaceVersion(): String {
    val cargoToml = rootProject.file("../../../Cargo.toml")
    if (!cargoToml.exists()) {
        logger.warn("Could not find workspace Cargo.toml at ${cargoToml.path}; defaulting to 0.0.0")
        return "0.0.0"
    }
    val text = cargoToml.readText()
    val sectionStart = text.indexOf("[workspace.package]")
    if (sectionStart == -1) {
        logger.warn("Cargo.toml has no [workspace.package] section; defaulting to 0.0.0")
        return "0.0.0"
    }
    val sectionEnd = text.indexOf('[', sectionStart + 1).let { if (it == -1) text.length else it }
    val section = text.substring(sectionStart, sectionEnd)
    return Regex("""(?m)^\s*version\s*=\s*"([^"]+)"""")
        .find(section)
        ?.groupValues
        ?.get(1)
        ?: "0.0.0".also {
            logger.warn("Could not parse version from [workspace.package]; defaulting to 0.0.0")
        }
}

fun versionCodeFor(semver: String): Int {
    val parts = semver.substringBefore('-')
        .split(".")
        .map { it.toIntOrNull() ?: 0 }
    val major = parts.getOrElse(0) { 0 }
    val minor = parts.getOrElse(1) { 0 }
    val patch = parts.getOrElse(2) { 0 }
    return major * 10_000 + minor * 100 + patch
}

val rvpnVersion = workspaceVersion()

android {
    namespace = "org.rvpn.client"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.rvpn.client"
        minSdk = 29 // Android 10+
        targetSdk = 34
        versionCode = versionCodeFor(rvpnVersion)
        versionName = rvpnVersion

        ndk {
            abiFilters.addAll(listOf("arm64-v8a", "x86_64", "armeabi-v7a"))
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
}