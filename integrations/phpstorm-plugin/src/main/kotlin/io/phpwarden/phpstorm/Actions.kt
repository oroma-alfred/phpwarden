package io.phpwarden.phpstorm

import com.google.gson.JsonParser
import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.application.ReadAction
import com.intellij.openapi.project.DumbAwareAction
import com.intellij.openapi.project.ProjectManager
import com.intellij.openapi.vfs.newvfs.BulkFileListener
import com.intellij.openapi.vfs.newvfs.events.VFileContentChangeEvent
import com.intellij.openapi.vfs.newvfs.events.VFileEvent
import com.intellij.psi.PsiManager

class RescanAction : DumbAwareAction() {
    override fun actionPerformed(e: AnActionEvent) {
        Cli.reset()
        ResultCache.clear()
        e.project?.let { DaemonCodeAnalyzer.getInstance(it).restart() }
    }
}

class FeedStatusAction : DumbAwareAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project
        ApplicationManager.getApplication().executeOnPooledThread {
            val res = Cli.run(listOf("feed", "status", "--json"), null, 60_000)
            if (res.notFound) { Cli.cliMissing(project); return@executeOnPooledThread }
            try {
                val s = JsonParser.parseString(res.stdout).asJsonObject
                fun f(k: String) = s.get(k)?.takeIf { !it.isJsonNull }?.asString ?: "?"
                Cli.notify(project, Parse.esc("Feed ${f("feed_version")} (${f("channel")}, ${f("source")}): " +
                    "${f("total_advisories")} advisories, ${f("composer_count")} Composer."))
            } catch (ex: Exception) {
                Cli.notify(project, Parse.esc("feed status failed: ${res.stderr.ifBlank { res.stdout }}"), NotificationType.ERROR)
            }
        }
    }
}

/** A saved composer.lock / .php file changes on disk without a PSI change, so restart highlighting for it. */
class SaveListener : BulkFileListener {
    override fun after(events: List<VFileEvent>) {
        val s = PhpwardenSettings.get()
        if (!s.enabled || !s.runOnSave) return
        val files = events.filterIsInstance<VFileContentChangeEvent>().map { it.file }
            .filter { it.name == "composer.lock" || it.extension.equals("php", ignoreCase = true) }
        if (files.isEmpty()) return
        for (project in ProjectManager.getInstance().openProjects) {
            if (project.isDisposed) continue
            val daemon = DaemonCodeAnalyzer.getInstance(project)
            for (vf in files) {
                if (!vf.isValid) continue
                val psi = ReadAction.compute<com.intellij.psi.PsiFile?, RuntimeException> {
                    PsiManager.getInstance(project).findFile(vf)
                } ?: continue
                daemon.restart(psi)
            }
        }
    }
}
