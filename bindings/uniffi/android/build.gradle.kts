// AAR ядра для Android: Kotlin-биндинги и библиотеки, которые собирает bindings/build.sh android.
//   ./gradlew assembleRelease       - build/outputs/aar/inkvault-core-android-release.aar
//   ./gradlew publishToMavenLocal   - для проверки клиента с неопубликованным ядром
//   ./gradlew publish               - в реестр пакетов GitLab, только в CI
plugins {
    id("com.android.library") version "9.2.1"
    `maven-publish`
}

// версия общая для всех сборок ядра и берется из [workspace.package] корневого Cargo.toml
val coreVersion = rootDir.resolve("../../../Cargo.toml").readLines()
    .first { it.startsWith("version = ") }
    .substringAfter('"').substringBefore('"')

group = "dev.inkov.inkvault"
version = coreVersion

android {
    namespace = "dev.inkov.inkvault.core"
    compileSdk = 37

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            kotlin.directories.add("../kotlin")
            jniLibs.directories.add("../jniLibs")
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    // AAR-вариант JNA содержит libjnidispatch.so для Android, обычный JAR - только для настольных систем
    api("net.java.dev.jna:jna:5.19.1@aar")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "inkvault-core-android"
            afterEvaluate { from(components["release"]) }
        }
    }
    repositories {
        val api = System.getenv("CI_API_V4_URL")
        if (api != null) {
            maven("$api/projects/${System.getenv("CI_PROJECT_ID")}/packages/maven") {
                name = "gitlab"
                credentials(HttpHeaderCredentials::class) {
                    name = "Job-Token"
                    value = System.getenv("CI_JOB_TOKEN")
                }
                authentication {
                    create<HttpHeaderAuthentication>("header")
                }
            }
        }
    }
}
