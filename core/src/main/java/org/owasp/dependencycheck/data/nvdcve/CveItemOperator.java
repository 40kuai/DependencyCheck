package org.owasp.dependencycheck.data.nvdcve;

import java.util.stream.Collectors;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;

import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;

/**
 *
 * Utility for processing {@linkplain DefCveItem} in order to extract key values
 * like textual description and ecosystem type.
 *
 */
public class CveItemOperator {

    public String extractDescription(DefCveItem cve) {
        return cve.getCve().getDescription().getDescriptionData().stream().filter((desc)
                -> "en".equals(desc.getLang())).map(d
                -> d.getValue()).collect(Collectors.joining(" "));
    }

    /**
     * Attempts to determine the ecosystem based on the vendor, product and
     * targetSw.
     *
     * @param baseEcosystem the base ecosystem
     * @param vendor the vendor
     * @param product the product
     * @param targetSw the target software
     * @return the ecosystem if one is identified
     */
    private String extractEcosystem(String baseEcosystem, String vendor, String product, String targetSw) {
        if ("ibm".equals(vendor) && "java".equals(product)) {
            return Ecosystem.NATIVE;
        }
        if ("oracle".equals(vendor) && "vm".equals(product)) {
            return Ecosystem.NATIVE;
        }
        switch (targetSw) {
            case "asp.net"://.net
            case "c#"://.net
            case ".net"://.net
            case "dotnetnuke"://.net
                return Ecosystem.DOTNET;
            case "android"://android
            case "java"://java
                return Ecosystem.JAVA;
            case "c/c++"://c++
            case "borland_c++"://c++
            case "visual_c++"://c++
            case "gnu_c++"://c++
            case "linux_kernel"://native
            case "linux"://native
            case "unix"://native
            case "suse_linux"://native
            case "redhat_enterprise_linux"://native
            case "debian"://native
                return Ecosystem.NATIVE;
            case "coldfusion"://coldfusion
                return Ecosystem.COLDFUSION;
            case "ios"://ios
            case "iphone"://ios
            case "ipad"://ios
            case "iphone_os"://ios
                return Ecosystem.IOS;
            case "jquery"://javascript
                return Ecosystem.JAVASCRIPT;
            case "node.js"://node.js
            case "nodejs"://node.js
                return Ecosystem.NODEJS;
            case "perl"://perl
                return Ecosystem.PERL;
            case "joomla!"://php
            case "joomla"://php
            case "mybb"://php
            case "simplesamlphp"://php
            case "craft_cms"://php
            case "moodle"://php
            case "phpcms"://php
            case "buddypress"://php
            case "typo3"://php
            case "php"://php
            case "wordpress"://php
            case "drupal"://php
            case "mediawiki"://php
            case "symfony"://php
            case "openpne"://php
            case "vbulletin3"://php
            case "vbulletin4"://php
                return Ecosystem.PHP;
            case "python"://python
                return Ecosystem.PYTHON;
            case "ruby"://ruby
                return Ecosystem.RUBY;
        }
        return baseEcosystem;
    }

    public String extractEcosystem(String baseEcosystem, VulnerableSoftware parsedCpe) {
        return extractEcosystem(baseEcosystem, parsedCpe.getVendor(), parsedCpe.getProduct(), parsedCpe.getTargetSw());
    }

    public boolean isRejected(String description) {
        return description.startsWith("** REJECT **");
    }

}
