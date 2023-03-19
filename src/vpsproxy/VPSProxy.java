package vpsproxy;

import java.util.HashMap;
import java.util.Map;
import burp.IBurpExtenderCallbacks;
import vpsproxy.providers.DigitalOceanProvider;
import vpsproxy.providers.Provider.ProviderException;
import vpsproxy.providers.*;

public class VPSProxy {
    private IBurpExtenderCallbacks callbacks;
    private VPSProxyTab optionsTab;
    private boolean clearProxy;

    private Map<String, Provider> providerMap;

    public VPSProxy(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        providerMap = new HashMap<String, Provider>();

        Provider awsProvider = new AWSProvider(callbacks);
        providerMap.put(awsProvider.getName(), awsProvider);

        Provider digitalOceanProvider = new DigitalOceanProvider(callbacks);
        providerMap.put(digitalOceanProvider.getName(), digitalOceanProvider);

        optionsTab = new VPSProxyTab(this, providerMap);

        Logger.init(callbacks.getStdout(), optionsTab);
    }

    public VPSProxyTab getUI() {
        return optionsTab;
    }

    public void close() {
        String destroyProxy = callbacks.loadExtensionSetting("DestroyProxy");
        if (destroyProxy == null || destroyProxy.equals("true")) {
            Provider currentProvider = optionsTab.getSelectedProvider();
            if (currentProvider != null) {
                try {
                    destroyInstance(currentProvider);
                } catch (ProviderException e) {
                } catch (Exception e) {
                    Logger.log(String.format("Unhandled exception: %s", e.getMessage()));
                }
            }
        }
    }

    protected IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    protected void startInstance(Provider provider) throws ProviderException {
        try {
            ProxySettings proxy = provider.startInstance();
            configureProxy(proxy);
        } catch (ProviderException e) {
            Logger.log(e.getMessage());
            throw e;
        } catch (Exception e) {
            Logger.log(String.format("Unhandled exception: %s", e.getMessage()));
            throw e;
        }
    }

    protected void destroyInstance(Provider provider) throws ProviderException {
        try {
            provider.destroyInstance();
            clearProxy();
            optionsTab.setStoppedState();
        } catch (ProviderException e) {
            Logger.log(e.getMessage());
            throw e;
        } catch (Exception e) {
            Logger.log(String.format("Unhandled exception: %s", e.getMessage()));
            throw e;
        }
    }

    protected void configureProxy(ProxySettings proxy) {
        Logger.log(String.format("Configuring proxy %s:%s:%s:%s", proxy.getIp(), proxy.getPort(), proxy.getUsername(), proxy.getPassword()));
        Logger.log("Proxy configured. The VPS could still be provisioning, please give it a few minutes.");

        String config = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":false,\"host\":\"IPADDRESS\",\"password\":\"PASSWORD\",\"port\":PORT,\"use_proxy\":true,\"use_user_options\":false,\"username\":\"USERNAME\"}}}}";
        config = config.replace("IPADDRESS", proxy.getIp())
                    .replace("PORT", proxy.getPort())
                    .replace("USERNAME", proxy.getUsername())
                    .replace("PASSWORD", proxy.getPassword());

        callbacks.loadConfigFromJson(config);

        clearProxy = true;
    }

    protected void clearProxy() {
        if (!clearProxy) {
            return;
        }

        Logger.log("Clearing proxy settings");

        String config = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":false,\"host\":\"0.0.0.0\",\"password\":\"\",\"port\":1080,\"use_proxy\":false,\"use_user_options\":false,\"username\":\"\"}}}}";
        callbacks.loadConfigFromJson(config);

        clearProxy = false;
    }
}
