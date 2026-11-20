plugins {
    java
}

group = "pro.hirdman"
version = "0.1.0"

repositories {
    mavenCentral()
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
    // A dialog in a test fails it instead of opening a window on the developer's screen.
    systemProperty("java.awt.headless", "true")
    // ProjectRulesTest reads the sources and READMEs, so a comment change reruns it.
    inputs.dir("src/main").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.files(fileTree(".") { include("README*.md") }).withPathSensitivity(PathSensitivity.RELATIVE)
}

tasks.jar {
    archiveBaseName = "hirdman-radar"
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    // Gson goes inside the jar: Burp loads a single file.
    from(configurations.runtimeClasspath.map { cp -> cp.map { zipTree(it) } }) {
        exclude("META-INF/*.SF", "META-INF/*.RSA", "META-INF/*.DSA", "**/module-info.class")
    }
    // The bundled libraries' licenses travel with them; update the notice when their versions change.
    from("THIRD-PARTY-NOTICES.txt") { into("META-INF") }
    from("licenses") { into("META-INF/licenses") }
}
