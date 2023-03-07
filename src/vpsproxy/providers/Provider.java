package vpsproxy.providers;

import javax.swing.JComponent;
import vpsproxy.ProxySettings;

public interface Provider {
    String getName();
    void startInstance();
    void destroyInstance();
    ProviderStatus getStatus();
    JComponent getUI();
    ProxySettings getProxy();
}
