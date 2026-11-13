<div class="phpwarden-panel">
    <h3>Security summary</h3>

    {if $embedUrl}
        <iframe
            src="{$embedUrl|escape:'html'}"
            title="phpwarden security summary"
            sandbox="allow-popups"
            referrerpolicy="no-referrer"
            loading="lazy"
            style="width:100%;height:520px;border:1px solid #ddd;border-radius:4px;"></iframe>
    {else}
        <div class="alert alert-warning">
            {if $embedError}{$embedError|escape:'html'}{else}The security summary is not available right now.{/if}
        </div>
    {/if}

    <h4>Connect your site</h4>
    {if $token}
        <p><strong>WordPress:</strong> install the <em>phpwarden</em> plugin, open its settings page and paste this token:</p>
        <pre>{$token|escape:'html'}</pre>
        <p><strong>Command line:</strong> run this on the server that hosts the site, replacing <code>/path</code> with the WordPress directory:</p>
        <pre>phpwarden wordpress /path --report-to {$reportUrl|escape:'html'} --report-token {$token|escape:'html'}</pre>
        <p>The summary above fills in after the first report arrives.</p>
    {else}
        <p>Your site token is not available yet. Please contact support to have it issued.</p>
    {/if}
</div>
