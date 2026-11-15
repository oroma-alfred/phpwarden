package io.phpwarden.phpstorm

import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.editor.Document
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.TextRange
import com.intellij.openapi.wm.WindowManager
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiFile
import java.awt.datatransfer.StringSelection
import java.io.File
import java.net.URI

/** Snapshot taken on the read thread; the CLI runs later on a background thread. */
data class ScanInfo(val project: Project, val path: String, val stamp: Long, val unsaved: Boolean, val text: String)

private fun snapshot(file: PsiFile): ScanInfo? {
    val vf = file.virtualFile ?: return null
    if (!vf.isInLocalFileSystem) return null
    val doc = PsiDocumentManager.getInstance(file.project).getDocument(file)
    val unsaved = doc != null && FileDocumentManager.getInstance().isDocumentUnsaved(doc)
    return ScanInfo(file.project, vf.path, vf.timeStamp, unsaved, doc?.text ?: "")
}

/**
 * Only call the CLI for the saved file on disk: while the editor has unsaved edits (or rescan-on-save is off
 * and we already have results) show the last results instead.
 */
private fun cachedOrRun(info: ScanInfo, compute: () -> List<Diag>?): List<Diag> {
    val prev = ResultCache.get(info.path)
    if (prev != null && (info.unsaved || prev.stamp == info.stamp || !PhpwardenSettings.get().runOnSave)) {
        return prev.diags
    }
    if (prev == null && info.unsaved) return emptyList()
    val diags = compute() ?: return prev?.diags ?: emptyList()
    ResultCache.put(info.path, ResultCache.Entry(info.stamp, diags))
    return diags
}

private fun severity(l: Level): HighlightSeverity = when (l) {
    Level.ERROR -> HighlightSeverity.ERROR
    Level.WARNING -> HighlightSeverity.WARNING
    Level.INFO -> HighlightSeverity.WEAK_WARNING
}

private fun rangeOf(doc: Document, d: Diag): TextRange? {
    if (doc.lineCount == 0) return null
    val line = d.line.coerceIn(0, doc.lineCount - 1)
    val ls = doc.getLineStartOffset(line)
    val le = doc.getLineEndOffset(line)
    val s = (ls + d.column).coerceIn(ls, le)
    var e = (ls + d.endColumn).coerceIn(s, le)
    if (e == s) {
        // Zero-width: underline to end of line (SARIF results often give only a start column).
        e = if (le > s) le else return TextRange(ls, le)
    }
    return TextRange(s, e)
}

private fun applyDiags(file: PsiFile, diags: List<Diag>, holder: AnnotationHolder) {
    val doc = PsiDocumentManager.getInstance(file.project).getDocument(file) ?: return
    for (d in diags) {
        val r = rangeOf(doc, d) ?: continue
        var b = holder.newAnnotation(severity(d.level), "phpwarden: ${d.message}")
            .range(r)
            .tooltip(d.tooltip)
        d.upgrade?.let { b = b.withFix(CopyUpgradeFix(it)) }
        b.create()
    }
}

class LockAnnotator : ExternalAnnotator<ScanInfo, List<Diag>>() {
    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): ScanInfo? = collect(file)
    override fun collectInformation(file: PsiFile): ScanInfo? = collect(file)

    private fun collect(file: PsiFile): ScanInfo? {
        val s = PhpwardenSettings.get()
        if (!s.enabled || !s.depsScan || file.name != "composer.lock") return null
        return snapshot(file)
    }

    override fun doAnnotate(info: ScanInfo): List<Diag> = cachedOrRun(info) {
        val lock = File(info.path)
        val res = Cli.run(listOf("deps", lock.path, "--json"), lock.parentFile)
        if (res.notFound) { Cli.cliMissing(info.project); return@cachedOrRun null }
        try {
            // Use the on-disk text so lines match what the CLI read.
            val text = runCatching { lock.readText() }.getOrDefault(info.text)
            Parse.depsToDiagnostics(Parse.parseDeps(res.stdout), text, PhpwardenSettings.get().minSeverity)
        } catch (e: Exception) {
            com.intellij.openapi.diagnostic.Logger.getInstance(LockAnnotator::class.java)
                .warn("phpwarden deps failed for ${info.path} (exit ${res.exitCode}): ${res.stderr}")
            null
        }
    }

    override fun apply(file: PsiFile, annotationResult: List<Diag>, holder: AnnotationHolder) =
        applyDiags(file, annotationResult, holder)
}

class CodeAnnotator : ExternalAnnotator<ScanInfo, List<Diag>>() {
    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): ScanInfo? = collect(file)
    override fun collectInformation(file: PsiFile): ScanInfo? = collect(file)

    private fun collect(file: PsiFile): ScanInfo? {
        val s = PhpwardenSettings.get()
        if (!s.enabled || !s.codeScan || Cli.codeUnsupported) return null
        return snapshot(file)
    }

    override fun doAnnotate(info: ScanInfo): List<Diag> = cachedOrRun(info) {
        val target = File(info.path)
        val base = target.parentFile
        val res = Cli.run(listOf("code", target.path, "--format", "sarif"), base)
        if (res.notFound) { Cli.cliMissing(info.project); return@cachedOrRun null }
        val all = try {
            Parse.sarifToDiagnostics(res.stdout)
        } catch (e: Exception) {
            if (Parse.looksLikeMissingSubcommand(res.stderr)) {
                Cli.codeUnsupported = true
                Cli.notify(info.project, "<code>phpwarden code</code> needs phpwarden 2.2.0 or newer; PHP file scans are off until the CLI is upgraded.")
            } else {
                com.intellij.openapi.diagnostic.Logger.getInstance(CodeAnnotator::class.java)
                    .warn("phpwarden code failed for ${info.path} (exit ${res.exitCode}): ${res.stderr}")
            }
            return@cachedOrRun null
        }
        // SARIF uris are relative to the scan target's directory (%SRCROOT%) or absolute file: URIs.
        val want = target.canonicalPath
        all.filter { d ->
            val f = d.file ?: return@filter false
            val resolved = if (f.startsWith("file:")) File(URI(f)) else File(base, java.net.URLDecoder.decode(f, "UTF-8"))
            runCatching { resolved.canonicalPath == want }.getOrDefault(false)
        }
    }

    override fun apply(file: PsiFile, annotationResult: List<Diag>, holder: AnnotationHolder) =
        applyDiags(file, annotationResult, holder)
}

class CopyUpgradeFix(private val cmd: String) : IntentionAction {
    override fun getText() = "Copy upgrade command: $cmd"
    override fun getFamilyName() = "phpwarden"
    override fun isAvailable(project: Project, editor: Editor?, file: PsiFile?) = true
    override fun startInWriteAction() = false
    override fun invoke(project: Project, editor: Editor?, file: PsiFile?) {
        CopyPasteManager.getInstance().setContents(StringSelection(cmd))
        WindowManager.getInstance().getStatusBar(project)?.info = "Copied: $cmd"
    }
}
