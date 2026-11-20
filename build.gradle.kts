plugins {
    java
}

group = "pro.hirdman"
version = "0.1.0"

repositories {
    mavenCentral()
}

// One compiler for every build, so the same commit gives the same jar.
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
        vendor = JvmVendorSpec.ADOPTIUM
    }
}

val montoya = "net.portswigger.burp.extensions:montoya-api:2026.7"

dependencies {
    // Burp provides the Montoya API at runtime, so it stays out of the jar.
    compileOnly(montoya)
    testImplementation(montoya)
    implementation("com.google.code.gson:gson:2.15.0")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 21
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all,-serial", "-Werror"))
}

tasks.processResources {
    val pluginVersion = project.version.toString()
    inputs.property("version", pluginVersion)
    filesMatching("radar-version.properties") {
        expand("version" to pluginVersion)
    }
}

tasks.test {
    useJUnitPlatform()
    // -PtestJava=25 runs the tests on a newer JDK; the classes are still built by the toolchain.
    providers.gradleProperty("testJava").orNull?.let { v ->
        javaLauncher = javaToolchains.launcherFor { languageVersion = JavaLanguageVersion.of(v) }
    }
    // A dialog in a test fails it instead of opening a window on the developer's screen.
    systemProperty("java.awt.headless", "true")
    // ProjectRulesTest reads the sources and READMEs, so a comment change reruns it.
    inputs.dir("src/main").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.files(fileTree(".") { include("README*.md") }).withPathSensitivity(PathSensitivity.RELATIVE)
}

// Gson's Error Prone annotations are for compilers only (Gson marks them optional), so neither the jar
// nor the tests carry them and the tests run Gson as Burp does.
listOf(configurations.runtimeClasspath, configurations.testRuntimeClasspath).forEach {
    it { exclude(group = "com.google.errorprone", module = "error_prone_annotations") }
}

tasks.jar {
    archiveBaseName = "hirdman-radar"
    // A second copy of a file is a build error, not a silent pick.
    duplicatesStrategy = DuplicatesStrategy.FAIL
    manifest {
        attributes(
            "Implementation-Title" to "Hirdman Radar",
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "HIRDMAN",
        )
    }
    // Gson goes inside the jar: Burp loads a single file.
    from(configurations.runtimeClasspath.map { cp -> cp.map { zipTree(it) } }) {
        exclude("META-INF/MANIFEST.MF", "META-INF/*.SF", "META-INF/*.RSA", "META-INF/*.DSA", "**/module-info.class")
    }
    // The bundled libraries' licenses travel with them; update the notice when their versions change.
    from("THIRD-PARTY-NOTICES.txt") { into("META-INF") }
    from("licenses") { into("META-INF/licenses") }
}
