package io.phpwarden.phpstorm

import com.intellij.execution.ExecutionException
import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.process.CapturingProcessHandler
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.project.Project
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap

data class RunResult(val stdout: String, val stderr: String, val exitCode: Int, val notFound: Boolean)

/** Runs the locally installed phpwarden CLI. Nothing is uploaded by the plugin itself. */
object Cli {
    private val log = Logger.getInstance(Cli::class.java)
    @Volatile private var warnedMissing = false
    @Volatile var codeUnsupported = false

    fun reset() { warnedMissing = false; codeUnsupported = false }

    fun run(args: List<String>, cwd: File?, timeoutMs: Int = 300_000): RunResult {
        val cmd = Parse.splitCommand(PhpwardenSettings.get().path)
        val gcl = GeneralCommandLine(cmd + args)
            .withCharset(StandardCharsets.UTF_8)
            .withParentEnvironmentType(GeneralCommandLine.ParentEnvironmentType.CONSOLE)
        if (cwd != null) gcl.withWorkDirectory(cwd)
        return try {
            val out = CapturingProcessHandler(gcl).runProcess(timeoutMs)
            if (out.isTimeout) log.warn("phpwarden timed out: ${gcl.commandLineString}")
            RunResult(out.stdout, out.stderr, out.exitCode, false)
        } catch (e: ExecutionException) {
            log.info("phpwarden could not start: ${e.message}")
            RunResult("", e.message ?: "", -1, true)
        }
    }

    fun cliMissing(project: Project?) {
        if (warnedMissing) return
        warnedMissing = true
        notify(project, "phpwarden CLI not found. Install it with <code>pipx install phpwarden</code>, " +
            "or set the path under Settings | Tools | phpwarden.", NotificationType.WARNING)
    }

    fun notify(project: Project?, html: String, type: NotificationType = NotificationType.INFORMATION) {
        NotificationGroupManager.getInstance().getNotificationGroup("phpwarden")
            .createNotification("phpwarden", html, type).notify(project)
    }
}

/** Last results per file path, keyed by the on-disk timestamp they were computed for. */
object ResultCache {
    data class Entry(val stamp: Long, val diags: List<Diag>)
    private val map = ConcurrentHashMap<String, Entry>()
    fun get(path: String): Entry? = map[path]
    fun put(path: String, e: Entry) { map[path] = e }
    fun clear() = map.clear()
}
