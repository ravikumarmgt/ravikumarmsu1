<?php

namespace Mgt\Waf\Model\Config\BackendModel;

use Mgt\Waf\Model\Config\BackendModel\Value as ConfigValue;
use Mgt\Waf\Model\Aws\Waf as AwsWaf;

class RateLimitWhitelistedIps extends ConfigValue
{
    protected function _afterLoad()
    {
        $sessionConfigData = $this->getSessionConfigData();
        $value = '';
        if (true === isset($sessionConfigData['groups']['rate_limit']['fields']['whitelisted_ips']['value'])) {
            $value = $sessionConfigData['groups']['rate_limit']['fields']['whitelisted_ips']['value'];
        } else {
            $awsAccessKey = $this->getAwsAccessKey();
            $projectName = $this->getProjectName();
            if (false === empty($awsAccessKey) && false === empty($projectName)) {
                $awsSecretAccessKey = $this->getAwsSecretAccessKey();
                $awsRegion = $this->getAwsRegion();
                $whitelistedIps = [];
                $awsWaf = new AwsWaf($awsAccessKey, $awsSecretAccessKey, $awsRegion, $projectName);
                $rateLimitWhitelistedIpv4 = $awsWaf->getIpAddressesForIpSet(AwsWaf::IP_SET_RATE_LIMIT_WHITELISTED_IPV4);
                if (false === empty($rateLimitWhitelistedIpv4)) {
                    foreach ($rateLimitWhitelistedIpv4 as $ip) {
                        if (substr($ip, -3) == '/32') {
                            $whitelistedIps[] = substr($ip, 0, -3);
                        }
                    }
                }
                $rateLimitWhitelistedIpv6 = $awsWaf->getIpAddressesForIpSet(AwsWaf::IP_SET_RATE_LIMIT_WHITELISTED_IPV6);
                if (false === empty($rateLimitWhitelistedIpv6)) {
                    foreach ($rateLimitWhitelistedIpv6 as $ip) {
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
