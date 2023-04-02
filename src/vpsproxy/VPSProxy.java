package vpsproxy;

import java.util.Map;
import java.util.LinkedHashMap;
import burp.IBurpExtenderCallbacks;
import vpsproxy.providers.DigitalOceanProvider;
import vpsproxy.providers.Provider.ProviderException;
import vpsproxy.providers.*;

public class VPSProxy {
    private static final String PROXY_CONFIG_TEMPLATE = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":false,\"host\":\"%s\",\"password\":\"%s\",\"port\":%s,\"use_proxy\":true,\"use_user_options\":false,\"username\":\"%s\"}}}}";

    private IBurpExtenderCallbacks callbacks;
    private VPSProxyTab optionsTab;

    private Map<String, Provider> providerMap;

    public VPSProxy(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        createBurpInstanceId();

        providerMap = new LinkedHashMap<>();
        addProvider(new AWSProvider(callbacks));
        addProvider(new DigitalOceanProvider(callbacks));
        addProvider(new LinodeProvider(callbacks));

        optionsTab = new VPSProxyTab(this, providerMap);
        Logger.init(callbacks.getStdout(), optionsTab);
    }

    public VPSProxyTab getUI() {
        return optionsTab;
    }

    public void close() {
        String destroyProxySetting = callbacks.loadExtensionSetting(SettingsKeys.DESTROY_PROXY_ON_EXIT);
        boolean destroyProxy = destroyProxySetting == null || Boolean.parseBoolean(destroyProxySetting);

        if (!destroyProxy)
            return;

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
            resetProxySettings();
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
        Logger.log(String.format("Configuring proxy %s:%s:%s:%s", proxy.getIp(), proxy.getPort(), proxy.getUsername(),
                proxy.getPassword()));

        String configBackup = callbacks.saveConfigAsJson("project_options.connections.socks_proxy");
        callbacks.saveExtensionSetting(SettingsKeys.PROXY_SETTINGS_BACKUP, configBackup);

        String config = String.format(PROXY_CONFIG_TEMPLATE, proxy.getIp(), proxy.getPassword(), proxy.getPort(),
                proxy.getUsername());
        callbacks.loadConfigFromJson(config);

        Logger.log("Proxy configured. The VPS could still be provisioning, please give it a few minutes.");
    }

    protected void resetProxySettings() {
        String config = callbacks.loadExtensionSetting(SettingsKeys.PROXY_SETTINGS_BACKUP);
        if (config != null) {
            Logger.log("Restoring proxy settings");
            callbacks.loadConfigFromJson(config);
            callbacks.saveExtensionSetting(SettingsKeys.PROXY_SETTINGS_BACKUP, null);
        }
    }

    private void createBurpInstanceId() {
        String instanceId = callbacks.loadExtensionSetting(SettingsKeys.BURP_INSTANCE_ID);

        if (instanceId == null) {
            String id = RandomString.generate(6);
            callbacks.saveExtensionSetting(SettingsKeys.BURP_INSTANCE_ID, id);
        }
    }

    private void addProvider(Provider provider) {
        providerMap.put(provider.getName(), provider);
    }
}
