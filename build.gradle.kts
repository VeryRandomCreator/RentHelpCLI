plugins {
    id("java")
    id("application")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

application {
    mainClass.set("com.veryrandomcreator.Main")
}

group = "com.veryrandomcreator"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.83")
    implementation("com.google.guava:guava:33.0.0-jre")
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}