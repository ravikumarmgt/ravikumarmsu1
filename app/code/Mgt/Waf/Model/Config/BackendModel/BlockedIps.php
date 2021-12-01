<?php

namespace Mgt\Waf\Model\Config\BackendModel;

use Mgt\Waf\Model\Config\BackendModel\Value as ConfigValue;
use Mgt\Waf\Model\Aws\Waf as AwsWaf;

class BlockedIps extends ConfigValue
{
    protected function _afterLoad()
    {
        $sessionConfigData = $this->getSessionConfigData();
        $value = '';
        if (true === isset($sessionConfigData['groups']['blocked_ips']['fields']['blocked_ips']['value'])) {
            $value = $sessionConfigData['groups']['blocked_ips']['fields']['blocked_ips']['value'];
        } else {
            $awsAccessKey = $this->getAwsAccessKey();
            $projectName = $this->getProjectName();
            if (false === empty($awsAccessKey) && false === empty($projectName)) {
                $awsSecretAccessKey = $this->getAwsSecretAccessKey();
                $awsRegion = $this->getAwsRegion();
                $blockedIps = [];
                $awsWaf = new AwsWaf($awsAccessKey, $awsSecretAccessKey, $awsRegion, $projectName);
                $blockedIpsIPv4 = $awsWaf->getIpAddressesForIpSet(AwsWaf::IP_SET_BLOCKED_IPS_IPV4);
                if (false === empty($blockedIpsIPv4)) {
                    foreach ($blockedIpsIPv4 as $ip) {
                        if (substr($ip, -3) == '/32') {
                            $blockedIps[] = substr($ip, 0, -3);
                        }
                    }
                }
                $blockedIpsIPv6 = $awsWaf->getIpAddressesForIpSet(AwsWaf::IP_SET_BLOCKED_IPS_IPV6);
                if (false === empty($blockedIpsIPv6)) {
                    foreach ($blockedIpsIPv6 as $ip) {
                        if (substr($ip, -4) == '/128') {
                            $blockedIps[] = substr($ip, 0, -4);
                        }
                    }
                }
                $value = implode(PHP_EOL, $blockedIps);
            }
        }
        $this->setValue($value);
    }
}
