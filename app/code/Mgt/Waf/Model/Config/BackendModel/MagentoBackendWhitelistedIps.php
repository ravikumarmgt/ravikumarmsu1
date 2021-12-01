<?php

namespace Mgt\Waf\Model\Config\BackendModel;

use Mgt\Waf\Model\Config\BackendModel\Value as ConfigValue;
use Mgt\Waf\Model\Aws\Waf as AwsWaf;

class MagentoBackendWhitelistedIps extends ConfigValue
{
    protected function _afterLoad()
    {
        $sessionConfigData = $this->getSessionConfigData();
        $value = '';
        if (true === isset($sessionConfigData['groups']['magento_backend']['fields']['whitelisted_ips']['value'])) {
            $value = $sessionConfigData['groups']['magento_backend']['fields']['whitelisted_ips']['value'];
        } else {
            $awsAccessKey = $this->getAwsAccessKey();
            $projectName = $this->getProjectName();
            if (false === empty($awsAccessKey) && false === empty($projectName)) {
                $awsSecretAccessKey = $this->getAwsSecretAccessKey();
                $awsRegion = $this->getAwsRegion();
                $whitelistedIps = [];
                $awsWaf = new AwsWaf($awsAccessKey, $awsSecretAccessKey, $awsRegion, $projectName);
                $magentoBackendWhitelistedIpv4 = $awsWaf->getIpAddressesForIpSet(AwsWaf::IP_SET_MAGENTO_BACKEND_WHITELISTED_IPV4);
                if (false === empty($magentoBackendWhitelistedIpv4)) {
                    foreach ($magentoBackendWhitelistedIpv4 as $ip) {
                        if (substr($ip, -3) == '/32') {
                            $whitelistedIps[] = substr($ip, 0, -3);
                        }
                    }
                }
                $magentoBackendWhitelistedIpv6 = $awsWaf->getIpAddressesForIpSet(AwsWaf::IP_SET_MAGENTO_BACKEND_WHITELISTED_IPV6);
                if (false === empty($magentoBackendWhitelistedIpv6)) {
                    foreach ($magentoBackendWhitelistedIpv6 as $ip) {
                        if (substr($ip, -4) == '/128') {
                            $whitelistedIps[] = substr($ip, 0, -4);
                        }
                    }
                }
                $value = implode(PHP_EOL, $whitelistedIps);
            }
        }
        $this->setValue($value);
    }
}
