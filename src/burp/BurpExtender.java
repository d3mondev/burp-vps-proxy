package burp;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        // Set our extension name
        this.callbacks.setExtensionName("VPS Proxy");

        // Register callback to destroy VPS when our extension is unloaded
        this.callbacks.registerExtensionStateListener(this);

        // Create new pane for the extension
        ITab optionsTab = new VPSProxyTab(callbacks);
        this.callbacks.addSuiteTab(optionsTab);
    }

    @Override
    public void extensionUnloaded() {
        this.callbacks.printOutput("extension unloaded");
    }
}
