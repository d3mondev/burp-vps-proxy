package vpsproxy.providers;

import javax.swing.JComponent;
import vpsproxy.ProxySettings;

public interface Provider {
    String getName();
    ProxySettings startInstance();
    void destroyInstance();
    JComponent getUI();
}
