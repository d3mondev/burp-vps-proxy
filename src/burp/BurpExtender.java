package burp;

public class BurpExtender implements IBurpExtender
{
    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("Burp Sample Extension Java");
    }
}
