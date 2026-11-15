package io.phpwarden.phpstorm

import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.ProjectManager
import com.intellij.openapi.ui.ComboBox
import com.intellij.ui.components.JBCheckBox
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import javax.swing.JComponent
import javax.swing.JPanel

@State(name = "PhpwardenSettings", storages = [Storage("phpwarden.xml")])
class PhpwardenSettings : PersistentStateComponent<PhpwardenSettings.S> {
    class S {
        var path: String = "phpwarden"
        var enabled: Boolean = true
        var depsScan: Boolean = true
        var codeScan: Boolean = true
        var runOnSave: Boolean = true
        var minSeverity: String = "low"
    }

    private var s = S()
    override fun getState(): S = s
    override fun loadState(state: S) { s = state }

    companion object {
        fun get(): S = ApplicationManager.getApplication().getService(PhpwardenSettings::class.java).state
    }
}

class PhpwardenConfigurable : Configurable {
    private val path = JBTextField()
    private val enabled = JBCheckBox("Enable phpwarden")
    private val deps = JBCheckBox("Scan composer.lock (phpwarden deps)")
    private val code = JBCheckBox("Scan PHP files (phpwarden code, needs phpwarden 2.2+)")
    private val onSave = JBCheckBox("Rescan on save (otherwise only on first open and Tools | phpwarden: Rescan)")
    private val minSev = ComboBox(arrayOf("low", "medium", "high", "critical"))
    private var panel: JPanel? = null

    override fun getDisplayName() = "phpwarden"

    override fun createComponent(): JComponent {
        path.emptyText.text = "phpwarden, vendor/bin/phpwarden, or python3 /path/to/phpwarden.pyz"
        val p = FormBuilder.createFormBuilder()
            .addLabeledComponent("phpwarden CLI:", path)
            .addComponent(enabled)
            .addComponent(deps)
            .addComponent(code)
            .addComponent(onSave)
            .addLabeledComponent("Hide dependency findings below:", minSev)
            .addTooltip("Known-exploited (CISA KEV) and EPSS >= 0.5 findings are always shown, as errors.")
            .addComponentFillVertically(JPanel(), 0)
            .panel
        panel = p
        reset()
        return p
    }

    override fun isModified(): Boolean {
        val s = PhpwardenSettings.get()
        return path.text != s.path || enabled.isSelected != s.enabled || deps.isSelected != s.depsScan ||
            code.isSelected != s.codeScan || onSave.isSelected != s.runOnSave || minSev.selectedItem != s.minSeverity
    }

    override fun apply() {
        val s = PhpwardenSettings.get()
        s.path = path.text.trim().ifEmpty { "phpwarden" }
        s.enabled = enabled.isSelected
        s.depsScan = deps.isSelected
        s.codeScan = code.isSelected
        s.runOnSave = onSave.isSelected
        s.minSeverity = minSev.selectedItem as String
        Cli.reset()
        ResultCache.clear()
        for (pr in ProjectManager.getInstance().openProjects) DaemonCodeAnalyzer.getInstance(pr).restart()
    }

    override fun reset() {
        val s = PhpwardenSettings.get()
        path.text = s.path
        enabled.isSelected = s.enabled
        deps.isSelected = s.depsScan
        code.isSelected = s.codeScan
        onSave.isSelected = s.runOnSave
        minSev.selectedItem = s.minSeverity
    }

    override fun disposeUIResources() { panel = null }
}
