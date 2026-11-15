package io.phpwarden.phpstorm

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser

// Pure logic (no IDE APIs) so it is unit-testable. Mirrors integrations/vscode/src/parse.ts.

enum class Level { ERROR, WARNING, INFO }

/** One entry of `phpwarden deps <lock> --json` -> vulnerable[] (src/phpwarden/cli.py). */
data class DepFinding(
    val pkg: String, val installed: String, val cve: String, val severity: String,
    val cvss: Double?, val knownExploited: Boolean, val ransomware: Boolean,
    val epss: Double?, val title: String, val fixed: List<String>, val reach: String,
)

data class Diag(
    val line: Int, val column: Int, val endColumn: Int, // 0-based
    val level: Level, val message: String, val code: String?,
    val file: String? = null, val upgrade: String? = null, val exploited: Boolean = false,
    val tooltip: String = message,
)

object Parse {
    private val SEV_RANK = mapOf("unknown" to 0, "low" to 1, "medium" to 2, "high" to 3, "critical" to 4)

    private fun JsonObject.str(k: String): String =
        get(k)?.takeIf { it.isJsonPrimitive }?.asString ?: ""
    private fun JsonObject.dbl(k: String): Double? =
        get(k)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asDouble
    private fun JsonObject.bool(k: String): Boolean =
        get(k)?.takeIf { it.isJsonPrimitive }?.asBoolean ?: false
    private fun JsonObject.obj(k: String): JsonObject? = get(k)?.takeIf { it.isJsonObject }?.asJsonObject

    fun parseDeps(json: String): List<DepFinding> {
        val root = JsonParser.parseString(json).asJsonObject
        val arr = root.get("vulnerable")?.takeIf { it.isJsonArray }?.asJsonArray ?: return emptyList()
        return arr.filter { it.isJsonObject }.map { it.asJsonObject }.map { o ->
            DepFinding(
                o.str("package"), o.str("installed"), o.str("cve"), o.str("severity"),
                o.dbl("cvss"), o.bool("known_exploited"), o.bool("ransomware"), o.dbl("epss"),
                o.str("title"),
                o.get("fixed")?.takeIf { it.isJsonArray }?.asJsonArray?.map(JsonElement::getAsString) ?: emptyList(),
                o.str("reach"),
            )
        }
    }

    fun isUrgent(f: DepFinding) = f.knownExploited || (f.epss != null && f.epss >= 0.5)

    /** KEV / EPSS >= 0.5 -> error; critical/high -> warning; everything else -> weak warning. */
    fun depLevel(f: DepFinding): Level = when {
        isUrgent(f) -> Level.ERROR
        f.severity.lowercase() in setOf("critical", "high") -> Level.WARNING
        else -> Level.INFO
    }

    /** Urgent findings always pass; "low" shows everything, including unknown severity. */
    fun passesMinSeverity(f: DepFinding, min: String): Boolean {
        if (isUrgent(f)) return true
        val m = SEV_RANK[min.lowercase()] ?: 1
        if (m <= 1) return true
        return (SEV_RANK[f.severity.lowercase()] ?: 0) >= m
    }

    private fun parts(v: String) = v.trim().removePrefix("v").removePrefix("V")
        .split('-', '+')[0].split('.').map { it.toIntOrNull() ?: 0 }

    fun compareVersions(a: String, b: String): Int {
        val x = parts(a)
        val y = parts(b)
        for (i in 0 until maxOf(x.size, y.size)) {
            val d = x.getOrElse(i) { 0 } - y.getOrElse(i) { 0 }
            if (d != 0) return if (d < 0) -1 else 1
        }
        return 0
    }

    /** Lowest fixed version strictly greater than installed. */
    fun pickFixed(installed: String, fixed: List<String>): String? =
        fixed.filter { compareVersions(it, installed) > 0 }.sortedWith { a, b -> compareVersions(a, b) }.firstOrNull()

    fun upgradeCommand(f: DepFinding): String? =
        pickFixed(f.installed, f.fixed)?.let { "composer require ${f.pkg}:^${it.removePrefix("v")}" }

    fun depMessage(f: DepFinding): String {
        val fixed = if (f.fixed.isNotEmpty()) f.fixed.joinToString(", ") else "no fix yet"
        val m = "${f.pkg} ${f.installed}: ${f.cve} ${f.title} — fixed in $fixed"
        return if (f.knownExploited) "[EXPLOITED] $m" else m
    }

    fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    fun depTooltip(f: DepFinding): String = buildString {
        append("<html><b>phpwarden</b>: ${esc(f.pkg)} ${esc(f.installed)}<br/>")
        append("<b>${esc(f.cve)}</b> ${esc(f.title)}<br/>")
        append("Severity: ${esc(f.severity)}")
        f.cvss?.takeIf { it > 0 }?.let { append(" (CVSS $it)") }
        f.epss?.let { append(", EPSS ${"%.3f".format(java.util.Locale.ROOT, it)}") }
        append("<br/>")
        if (f.knownExploited) append("<b>Known exploited (CISA KEV)</b><br/>")
        if (f.ransomware) append("Known ransomware use<br/>")
        append("Fixed in: ${if (f.fixed.isEmpty()) "no fix yet" else esc(f.fixed.joinToString(", "))}")
        upgradeCommand(f)?.let { append("<br/>Upgrade: <code>${esc(it)}</code>") }
        append("</html>")
    }

    /** Find the `"name": "<pkg>"` line in composer.lock text. Returns 0-based (line, startCol, endCol). */
    fun findPackageLine(lockText: String, pkg: String): Triple<Int, Int, Int>? {
        val needle = "\"${pkg.lowercase()}\""
        val re = Regex("\"name\"\\s*:\\s*")
        lockText.split(Regex("\r?\n")).forEachIndexed { i, raw ->
            val l = raw.lowercase()
            val m = re.find(l) ?: return@forEachIndexed
            val col = m.range.last + 1
            if (l.startsWith(needle, col)) return Triple(i, col, col + needle.length)
        }
        return null
    }

    fun depsToDiagnostics(findings: List<DepFinding>, lockText: String, minSeverity: String = "low"): List<Diag> =
        findings.filter { passesMinSeverity(it, minSeverity) }.map { f ->
            val (line, col, end) = findPackageLine(lockText, f.pkg) ?: Triple(0, 0, 1)
            Diag(line, col, end, depLevel(f), depMessage(f), f.cve, upgrade = upgradeCommand(f),
                exploited = f.knownExploited, tooltip = depTooltip(f))
        }

    /** SARIF 2.1.0 (`phpwarden code --format sarif`) -> diagnostics. Results without a location are skipped. */
    fun sarifToDiagnostics(json: String): List<Diag> {
        val runs = JsonParser.parseString(json).asJsonObject.get("runs")?.takeIf { it.isJsonArray }?.asJsonArray
        val run = runs?.firstOrNull()?.takeIf { it.isJsonObject }?.asJsonObject ?: return emptyList()
        val rules = HashMap<String, JsonObject>()
        run.obj("tool")?.obj("driver")?.get("rules")?.takeIf { it.isJsonArray }?.asJsonArray?.forEach {
            if (it.isJsonObject) rules[it.asJsonObject.str("id")] = it.asJsonObject
        }
        val out = ArrayList<Diag>()
        val results = run.get("results")?.takeIf { it.isJsonArray }?.asJsonArray ?: return out
        for (el in results) {
            if (!el.isJsonObject) continue
            val r = el.asJsonObject
            val loc = r.get("locations")?.takeIf { it.isJsonArray }?.asJsonArray?.firstOrNull()
                ?.takeIf { it.isJsonObject }?.asJsonObject
            val pl = loc?.obj("physicalLocation") ?: continue
            val uri = pl.obj("artifactLocation")?.str("uri")?.ifEmpty { null } ?: continue
            val region = pl.obj("region")
            val line = maxOf(0, (region?.dbl("startLine")?.toInt() ?: 1) - 1)
            val col = maxOf(0, (region?.dbl("startColumn")?.toInt() ?: 1) - 1)
            val endCol = region?.dbl("endColumn")?.let { maxOf(col + 1, it.toInt() - 1) } ?: (col + 1)
            val level = when (r.str("level")) {
                "error" -> Level.ERROR
                "note", "none" -> Level.INFO
                else -> Level.WARNING
            }
            val ruleId = r.str("ruleId")
            val msg = r.obj("message")?.str("text")?.ifEmpty { null } ?: ruleId.ifEmpty { "phpwarden finding" }
            val rule = rules[ruleId]
            val desc = rule?.obj("fullDescription")?.str("text").orEmpty()
            val help = rule?.obj("help")?.str("text").orEmpty()
            val tip = buildString {
                append("<html><b>phpwarden</b> [${esc(ruleId)}]: ${esc(msg)}")
                if (desc.isNotEmpty()) append("<br/>${esc(desc)}")
                if (help.isNotEmpty()) append("<br/><b>Fix:</b> ${esc(help)}")
                append("</html>")
            }
            out += Diag(line, col, endCol, level, msg, ruleId, file = uri, tooltip = tip)
        }
        return out
    }

    fun looksLikeMissingSubcommand(stderr: String) =
        Regex("invalid choice: 'code'|unrecognized arguments|argument cmd: invalid choice", RegexOption.IGNORE_CASE)
            .containsMatchIn(stderr)

    /** Split the CLI path setting into executable + leading args (supports `python3 /path/phpwarden.pyz`). */
    fun splitCommand(path: String): List<String> {
        val toks = Regex("\"[^\"]*\"|'[^']*'|\\S+").findAll(path.ifBlank { "phpwarden" })
            .map { it.value.removeSurrounding("\"").removeSurrounding("'") }.toList()
        return toks.ifEmpty { listOf("phpwarden") }
    }
}
