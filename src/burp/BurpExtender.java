package burp;

import vpsproxy.Logger;
import vpsproxy.VPSProxy;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private VPSProxy extension;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Logger.init(callbacks.getStdout(), null);

        // Set our extension name
        callbacks.setExtensionName("VPS Proxy");

        // Register callback to destroy VPS when our extension is unloaded
        callbacks.registerExtensionStateListener(this);

        // Create our main extension object
        extension = new VPSProxy(callbacks);
        callbacks.addSuiteTab(extension.getUI());
    }

    @Override
    public void extensionUnloaded() {
        extension.close();
    }
}
