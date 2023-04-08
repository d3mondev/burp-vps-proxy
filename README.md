<h3 align="center">Burp VPS Proxy: Easy Cloud Proxies for Burp Suite</h2>

<p align="center"><img src="assets/logo.png" width="800"></p>

<p align="center">
    <img src="https://img.shields.io/github/actions/workflow/status/d3mondev/burp-vps-proxy/main.yml?branch=main&style=for-the-badge">
    <img src="https://img.shields.io/badge/License-GPL3-green.svg?style=for-the-badge">
    <a href="https://twitter.com/d3mondev"><img src="https://img.shields.io/twitter/follow/d3mondev?logo=twitter&style=for-the-badge"></a>
</p>

<p align="center">
    <a href="#-how-to-use"><strong>Getting Started »</strong></a>
    <br />
    <br />
    <a href="#-features">Features</a>
    ·
    <a href="#-providers">Providers</a>
    ·
    <a href="#-disclaimers--license">Disclaimers</a>
</p>

# 📖 About

Burp VPS Proxy is a BurpSuite extension that allows for the automatic creation and deletion of upstream SOCKS5 proxies on popular cloud providers from within BurpSuite. It automatically configures Burp to use the created proxy so that all outbound traffic comes from a cloud IP address. This is useful to prevent our main IP address from being blacklisted by popular WAFs while performing penetration testing and bug bounty hunting.

Burp VPS Proxy was inspired by @honoki's awesome [DigitalOcean Droplet Proxy for Burp Suite](https://github.com/honoki/burp-digitalocean-droplet-proxy) idea.

# 🛠 Features

* Automatic creation, configuration and deletion of upstream SOCKS5 proxy on popular cloud services from within BurpSuite.
* Support for multiple providers: AWS, Digital Ocean and Linode.
* Each provider has its unique settings, including region selection.
* Automatic destruction of proxy when closing Burp or unloading the extension, with an option to preserve the proxy across sessions instead.
* Restores SOCKS5 proxy settings in Burp to their original values when the proxy is destroyed.
* Compatibility across multiple devices, ensuring seamless use without interference from proxies generated on separate computers.

# 🔎 How to use

Visit the [release page](https://github.com/d3mondev/burp-vps-proxy/releases) and download the latest `burp-vps-proxy.jar` file.

In BurpSuite, visit the Extensions tab and click Add. Set the extension type to Java, and select the `burp-vps-proxy.jar` file.

Once loaded, access the extension via the new VPS Proxy tab in Burp. Select your provider, set your API keys and click Deploy.

# 🌐 Providers

## Amazon Web Services (AWS)

![](assets/providers-aws.png)

The extension will use the `t4g.nano` instance type to minimize costs. Note that not all regions support this instance type. The extension will also create a security group named `burp-vps-proxy` in the region selected to allow connections to port 1080.

You will need an AWS Access Key and AWS Private Key in order to configure the extension. You'll also need to ensure the key pair gives access to at least the following permissions:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EC2Permissions",
            "Effect": "Allow",
            "Action": [
                "ec2:RunInstances",
                "ec2:TerminateInstances",
                "ec2:DescribeInstances",
                "ec2:DescribeImages",
                "ec2:DescribeRegions",
                "ec2:CreateTags",
                "ec2:CreateSecurityGroup",
                "ec2:DescribeSecurityGroups",
                "ec2:AuthorizeSecurityGroupIngress"
            ],
            "Resource": "*"
        }
    ]
}
```

## Digital Ocean

![](assets/providers-do.png)

Digital Ocean is a popular VPS provider among security researchers, pentesters and bug bounty hunters. If you don't already have an account, you can get a $200 in free credits by using my referral link to signup:

[![DigitalOcean Referral Badge](https://web-platforms.sfo2.digitaloceanspaces.com/WWW/Badge%203.svg)](https://www.digitalocean.com/?refcode=e4681a7c61c6&utm_campaign=Referral_Invite&utm_medium=Referral_Program&utm_source=badge)

You will need to create an API key and enter it in the Burp VPS Proxy extension.

Provisioning can take some time after the droplet is created. Wait a few minutes after the instance is up.

## Linode

![](assets/providers-linode.png)

You will need to create an API key and enter it in the Burp VPS Proxy extension. This is done in the "My Settings -> API Tokens" section of your profile in your Linode dashboard. They call it a Personal Access Token.

Ensure the API key has the Read/Write permission for "Linodes".

Provisioning is done via SSH and the proxy is usually available as soon as the extension tells you.

## SSH (experimental)

![](assets/providers-ssh.png)

The SSH provider enables the use of a remote SSH connection as a SOCKS5 proxy. Essentially, it performs the equivalent of `ssh -D` from within the VPS Proxy tab, adding extra convenience for users who prefer to use their own server.

Currently, only password authentication is supported. Simply enter your host and credentials, and the extension will create a SOCKS5 proxy on the specified local port and configure Burp Suite to use it.

# ⚖ Disclaimers & License

The author and contributors of this extension expressly disclaim any liability for any costs, damages, or consequences resulting from the use of cloud providers in connection with this software.

Using this program for unauthorized or illegal activities, including attacking targets without consent, is strictly prohibited. Users must comply with all applicable laws and regulations. The developer and contributors assume no liability or responsibility for any misuse, damage, or harm caused by this software. It is the user's responsibility to utilize this program in an ethical and lawful manner.

This repository's content is licensed under the GNU General Public License v3.0 (GPLv3).
