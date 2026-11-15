package io.phpwarden.phpstorm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Uses the VS Code extension's fixtures so both integrations agree on the CLI's output shapes. */
class ParseTest {
    private val fx = File("../vscode/test-fixtures")

    @Test fun deps() {
        val findings = Parse.parseDeps(File(fx, "deps.json").readText())
        assertEquals(4, findings.size)
        val diags = Parse.depsToDiagnostics(findings, File(fx, "composer.lock").readText())
        val kev = diags.first { it.code == "CVE-2022-24894" }
        assertEquals(Level.ERROR, kev.level)            // KEV -> error even though severity is medium
        assertTrue(kev.message.startsWith("[EXPLOITED]"))
        assertEquals("composer require symfony/http-kernel:^5.4.20", kev.upgrade)
        assertTrue(kev.tooltip.contains("Known exploited"))
        assertEquals(Level.WARNING, diags.first { it.code == "CVE-2022-29248" }.level)
        assertEquals(Level.ERROR, diags.first { it.code == "CVE-0000-0001" }.level) // EPSS >= 0.5
        assertNull(diags.first { it.code == "CVE-0000-0002" }.upgrade)
        assertEquals(3, Parse.depsToDiagnostics(findings, "", "medium").size) // low one hidden, urgent low kept
    }

    @Test fun sarif() {
        val d = Parse.sarifToDiagnostics(File(fx, "code.sarif").readText())
        assertEquals(2, d.size)
        assertEquals(Level.ERROR, d[0].level)
        assertEquals(11, d[0].line); assertEquals(4, d[0].column)
        assertEquals(Level.INFO, d[1].level)
    }

    @Test fun misc() {
        assertEquals(listOf("python3", "/a b/phpwarden.pyz"), Parse.splitCommand("python3 \"/a b/phpwarden.pyz\""))
        assertEquals("7.4.3", Parse.pickFixed("7.4.0", listOf("6.5.6", "7.4.3")))
        assertTrue(Parse.looksLikeMissingSubcommand("argument cmd: invalid choice: 'code'"))
    }
}
