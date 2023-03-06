package burp;

import vpsproxy.VPSProxy;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        // Set our extension name
        callbacks.setExtensionName("VPS Proxy");

        // Register callback to destroy VPS when our extension is unloaded
        callbacks.registerExtensionStateListener(this);

        // Create our main extension object
        VPSProxy extension = new VPSProxy(callbacks);
        callbacks.addSuiteTab(extension.getUI());
    }

    @Override
    public void extensionUnloaded() {
        callbacks.printOutput("extension unloaded");
    }
}
