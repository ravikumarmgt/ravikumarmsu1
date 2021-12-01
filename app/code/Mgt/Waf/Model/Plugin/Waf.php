<?php

namespace Mgt\Waf\Model\Plugin;

use Magento\Backend\Setup\ConfigOptionsList as BackendConfigOptionsList;
use Mgt\Waf\Model\Aws\Waf as AwsWaf;
use Mgt\Waf\Model\Util\Retry;

class Waf
{
    const MGT_WAF_CONFIG_DATA = 'mgtWafConfigData';
    const MGT_WAF_CONFIG_DATA_SECTION = 'mgt_waf';
    const MAGENTO_BACKEND_RESTRICTION_ENABLED = 1;
    const MAGENTO_BACKEND_RESTRICTION_DISABLED = 0;
    const MAGENTO_BACKEND_RESTRICTION_ACTION_ALLOW = 'Allow';
    const MAGENTO_BACKEND_RESTRICTION_ACTION_BLOCK = 'Block';

    protected $awsWaf;
    protected $configData = [];
    protected $awsAccessKey;
    protected $awsSecretAccessKey;
    protected $awsRegion;
    protected $blockedIps = [];
    protected $blockedCountryCodes = [];
    protected $blockedIpsIpv4 = [];
    protected $blockedIpsIpv6 = [];
    protected $blockedBots = [];
    protected $webAcl;
    protected $webAclName;
    protected $rateLimit;
    protected $rateLimitWhitelistedIps = [];
    protected $rateLimitWhitelistedIpsIpv4 = [];
    protected $rateLimitWhitelistedIpsIpv6 = [];
    protected $isMagentoBackendRestricted = false;
    protected $magentoBackendWhitelistedIps = [];
    protected $magentoBackendWhitelistedIpIpv4 = [];
    protected $magentoBackendWhitelistedIpIpv6 = [];
    protected $projectName;
    protected $deploymentConfig;
    protected $remoteAddress;
    protected $session;

    public function __construct(
        \Magento\Backend\Model\Session $session,
        \Magento\Framework\App\DeploymentConfig $deploymentConfig,
        \Magento\Framework\HTTP\PhpEnvironment\RemoteAddress $remoteAddress
    )
    {
        $this->session = $session;
        $this->deploymentConfig = $deploymentConfig;
        $this->remoteAddress = $remoteAddress;
    }

    /**
     * @param \Magento\Config\Model\Config $subject
     */
    public function beforeSave(\Magento\Config\Model\Config $subject)
    {
        try {
            $this->configData = $subject->getData();
            if (true === isset($this->configData['section']) && $this->configData['section'] == self::MGT_WAF_CONFIG_DATA_SECTION) {
                $isMgt = (true === isset($_SERVER['MGT']) && $_SERVER['MGT'] == '1' ? true : false);
                if (false === $isMgt) {
                    return;
                }
                $this->session->unsetData(self::MGT_WAF_CONFIG_DATA);
                $this->validate();
                $this->updateWaf();
            }
        } catch (\Exception $e) {
            $this->session->setData(self::MGT_WAF_CONFIG_DATA, $this->configData);
            throw $e;
        }
    }

    protected function validate()
    {
        $this->validateAccessKeys();
        $this->validateWebAcl();
        $this->validateBlockedIps();
        $this->validateRateLimit();
        $this->validateRateLimitWhitelistIps();
        $this->validateMagentoBackendWhitelistedIps();
    }

    protected function updateWaf()
    {
        try {
            $webAclName = $this->getWebAclName();
            $this->updateBlockedCountryCodes();
            $this->updateBlockedIpsIpSets();
            $this->updateBlockedBots();
            $this->updateRateLimitValue();
            $this->updateRateLimitWhitelistedIpSets();
            $this->updateMagentoBackend();
            $webAcl = $this->getWebAcl();
            $awsWaf = $this->getAwsWaf();
            $awsWaf->updateWebAcl($webAcl);
        } catch (\Exception $e) {
            $errorMessage = sprintf('Unable to update Web ACL "%s", error message: "%s".', $webAclName, $e->getMessage());
            throw new \Exception($errorMessage);
        }
    }

    protected function validateAccessKeys()
    {
        try {
            $awsWaf = $this->getAwsWaf();
            $wafClient = $awsWaf->getWafClient();
            $this->retry(function() use ($wafClient) {
                $wafClient->listIPSets([
                    'Scope' => AwsWaf::SCOPE_REGIONAL
                ]);
            });
        } catch (\Exception $e) {
            $errorMessage = sprintf('AWS Credentials are not valid.');
            throw new \Exception($errorMessage);
        }
    }

    protected function validateWebAcl()
    {
        $webAclFound = false;
        $webAclName = $this->getWebAclName();
        $awsWaf = $this->getAwsWaf();
        $webAcls = $awsWaf->getWebAcls();
        if (false === empty($webAcls)) {
            foreach ($webAcls as $webAcl) {
                if (true === isset($webAcl['Name']) && $webAclName == $webAcl['Name']) {
                    $webAclFound = true;
                    break;
                }
            }
        }
        if (false === $webAclFound) {
            $awsRegion = $this->getAwsRegion();
            $errorMessage = sprintf('Web Acl "%s" does not exist in AWS Region "%s".', $webAclName, $awsRegion);
            throw new \Exception($errorMessage);
        }
    }

    protected function validateBlockedIps()
    {
        $blockedIps = $this->getBlockedIps();
        if (false === empty($blockedIps)) {
            foreach ($blockedIps as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $this->blockedIpsIpv6[] = $ip;
                } else {
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $this->blockedIpsIpv4[] = $ip;
                    } else {
                        throw new \Exception(sprintf('Blocked IP "%s" is not valid.', $ip));
                    }
                }
            }
        }
    }

    protected function validateRateLimitWhitelistIps()
    {
        $rateLimitWhitelistedIps = $this->getRateLimitWhitelistedIps();
        if (false === empty($rateLimitWhitelistedIps)) {
            foreach ($rateLimitWhitelistedIps as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $this->rateLimitWhitelistedIpsIpv6[] = $ip;
                } else {
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $this->rateLimitWhitelistedIpsIpv4[] = $ip;
                    } else {
                        throw new \Exception(sprintf('Rate Limit Whitelisted IP "%s" is not valid.', $ip));
                    }
                }
            }
        }
    }

    protected function validateMagentoBackendWhitelistedIps()
    {
        $magentoBackendWhitelistedIps = $this->getMagentoBackendWhitelistedIps();
        if (false === empty($magentoBackendWhitelistedIps)) {
            foreach ($magentoBackendWhitelistedIps as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $this->magentoBackendWhitelistedIpIpv6[] = $ip;
                } else {
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $this->magentoBackendWhitelistedIpIpv4[] = $ip;
                    } else {
                        throw new \Exception(sprintf('Magento Backend Whitelisted IP "%s" is not valid.', $ip));
                    }
                }
            }
        }
    }

    protected function validateRateLimit()
    {
        $rateLimit = $this->getRateLimit();
        if (($rateLimit < 100) || ($rateLimit > 15000)) {
            throw new \Exception(sprintf('Rate Limit "%s" not valid, must be between 100 and 15000.', $rateLimit));
        }
    }

    protected function updateMagentoBackend()
    {
        $awsWaf = $this->getAwsWaf();
        $backendFrontName = $this->getBackendFrontName();
        $webAclRuleName = $awsWaf->getWebAclRuleName(AwsWaf::WEB_ACL_RULE_BLOCK_MAGENTO_BACKEND_ACCESS);
        $webAclRuleArrayIndex = $this->getWebAclRuleArrayIndex($webAclRuleName);
        if (true === isset($this->webAcl['Rules'][$webAclRuleArrayIndex])) {
            $isMagentoBackendRestricted = $this->isMagentoBackendRestricted();
            if (true === isset($this->webAcl['Rules'][$webAclRuleArrayIndex]['Action'])) {
                unset($this->webAcl['Rules'][$webAclRuleArrayIndex]['Action']);
            }
            $action = (true === $isMagentoBackendRestricted ? self::MAGENTO_BACKEND_RESTRICTION_ACTION_BLOCK : self::MAGENTO_BACKEND_RESTRICTION_ACTION_ALLOW);
            $this->webAcl['Rules'][$webAclRuleArrayIndex]['Action'][$action] = [];
            $this->webAcl['Rules'][$webAclRuleArrayIndex]['Statement']['ByteMatchStatement']['SearchString'] = $backendFrontName;
        }
        $webAclRuleName = $awsWaf->getWebAclRuleName(AwsWaf::WEB_ACL_RULE_ALLOW_MAGENTO_BACKEND_ACCESS_IPV4);
        $webAclRuleArrayIndex = $this->getWebAclRuleArrayIndex($webAclRuleName);
        if (true === isset($this->webAcl['Rules'][$webAclRuleArrayIndex])) {
            $this->webAcl['Rules'][$webAclRuleArrayIndex]['Statement']['AndStatement']['Statements'][0]['ByteMatchStatement']['SearchString'] = $backendFrontName;
        }
        $webAclRuleName = $awsWaf->getWebAclRuleName(AwsWaf::WEB_ACL_RULE_ALLOW_MAGENTO_BACKEND_ACCESS_IPV6);
        $webAclRuleArrayIndex = $this->getWebAclRuleArrayIndex($webAclRuleName);
        if (true === isset($this->webAcl['Rules'][$webAclRuleArrayIndex])) {
            $this->webAcl['Rules'][$webAclRuleArrayIndex]['Statement']['AndStatement']['Statements'][0]['ByteMatchStatement']['SearchString'] = $backendFrontName;
        }
        $isMagentoBackendRestricted = $this->isMagentoBackendRestricted();
        if (true === $isMagentoBackendRestricted) {
            $customerIp = $this->remoteAddress->getRemoteAddress();
            if (false === empty($customerIp)) {
                if (filter_var($customerIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $this->magentoBackendWhitelistedIpIpv6[] = $customerIp;
                } else {
                    $this->magentoBackendWhitelistedIpIpv4[] = $customerIp;
                }
            }
        }
        foreach ($this->magentoBackendWhitelistedIpIpv4 as &$ip) {
            $ip = sprintf('%s/32', $ip);
        }
        foreach ($this->magentoBackendWhitelistedIpIpv6 as &$ip) {
            $ip = sprintf('%s/128', $ip);
        }
        $awsWaf->updateIpSet(AwsWaf::IP_SET_MAGENTO_BACKEND_WHITELISTED_IPV4, $this->magentoBackendWhitelistedIpIpv4);
        $awsWaf->updateIpSet(AwsWaf::IP_SET_MAGENTO_BACKEND_WHITELISTED_IPV6, $this->magentoBackendWhitelistedIpIpv6);
    }

    protected function updateBlockedCountryCodes()
    {
        $blockedCountryCodes = $this->getBlockedCountryCodes();
        if (true === empty($blockedCountryCodes)) {
            $blockedCountryCodes = ['TV'];
        }
        $awsWaf = $this->getAwsWaf();
        $webAclRuleName = $awsWaf->getWebAclRuleName(AwsWaf::WEB_ACL_RULE_NAME_BLOCKED_COUNTRIES);
        $webAclRuleArrayIndex = $this->getWebAclRuleArrayIndex($webAclRuleName);
        if (true === isset($this->webAcl['Rules'][$webAclRuleArrayIndex])) {
            $this->webAcl['Rules'][$webAclRuleArrayIndex]['Statement']['GeoMatchStatement']['CountryCodes'] = $blockedCountryCodes;
        } else {
            throw new \Exception(sprintf('Web ACL Rule "%s" not found.', $webAclRuleName));
        }
    }

    protected function updateRateLimitValue()
    {
        $awsWaf = $this->getAwsWaf();
        $rateLimit = (int)$this->getRateLimit();
        $webAclRuleNameRateLimitIPv4 = $awsWaf->getWebAclRuleName(AwsWaf::WEB_ACL_RULE_NAME_RATE_LIMIT_IPV4);
        $webAclRuleArrayIndex = $this->getWebAclRuleArrayIndex($webAclRuleNameRateLimitIPv4);
        if (true === isset($this->webAcl['Rules'][$webAclRuleArrayIndex])) {
            $this->webAcl['Rules'][$webAclRuleArrayIndex]['Statement']['RateBasedStatement']['Limit'] = $rateLimit;
        } else {
            throw new \Exception(sprintf('Web ACL Rule "%s" not found.', $webAclRuleNameRateLimitIPv4));
        }
        $webAclRuleNameRateLimitIPv6 = $awsWaf->getWebAclRuleName(AwsWaf::WEB_ACL_RULE_NAME_RATE_LIMIT_IPV6);
        $webAclRuleArrayIndex = $this->getWebAclRuleArrayIndex($webAclRuleNameRateLimitIPv6);
        if (true === isset($this->webAcl['Rules'][$webAclRuleArrayIndex])) {
            $this->webAcl['Rules'][$webAclRuleArrayIndex]['Statement']['RateBasedStatement']['Limit'] = $rateLimit;
        } else {
            throw new \Exception(sprintf('Web ACL Rule "%s" not found.', $webAclRuleNameRateLimitIPv6));
        }
    }

    protected function updateRateLimitWhitelistedIpSets()
    {
        foreach ($this->rateLimitWhitelistedIpsIpv4 as &$ip) {
            $ip = sprintf('%s/32', $ip);
        }
        foreach ($this->rateLimitWhitelistedIpsIpv6 as &$ip) {
            $ip = sprintf('%s/128', $ip);
        }
        $awsWaf = $this->getAwsWaf();
        $awsWaf->updateIpSet(AwsWaf::IP_SET_RATE_LIMIT_WHITELISTED_IPV4, $this->rateLimitWhitelistedIpsIpv4);
        $awsWaf->updateIpSet(AwsWaf::IP_SET_RATE_LIMIT_WHITELISTED_IPV6, $this->rateLimitWhitelistedIpsIpv6);
    }

    protected function updateBlockedIpsIpSets()
    {
        foreach ($this->blockedIpsIpv4 as &$ip) {
            $ip = sprintf('%s/32', $ip);
        }
        foreach ($this->blockedIpsIpv6 as &$ip) {
            $ip = sprintf('%s/128', $ip);
        }
        $awsWaf = $this->getAwsWaf();
        $awsWaf->updateIpSet(AwsWaf::IP_SET_BLOCKED_IPS_IPV4, $this->blockedIpsIpv4);
        $awsWaf->updateIpSet(AwsWaf::IP_SET_BLOCKED_IPS_IPV6, $this->blockedIpsIpv6);
    }

    protected function updateBlockedBots()
    {
        $blockedBots = $this->getBlockedBots();
        if (true === empty($blockedBots)) {
            $blockedBots[] = 'mgt';
        }
        $awsWaf = $this->getAwsWaf();
        $awsWaf->updateBlockedBotsRegexPatternSet($blockedBots);
    }

    protected function getAwsWaf()
    {
        if (true === is_null($this->awsWaf)) {
            $awsAccessKey = $this->getAwsAccessKey();
            $awsSecretAccessKey = $this->getAwsSecretAccessKey();
            $awsRegion = $this->getAwsRegion();
            $projectName = $this->getProjectName();
            $this->awsWaf = new AwsWaf($awsAccessKey, $awsSecretAccessKey, $awsRegion, $projectName);
        }
        return $this->awsWaf;
    }

    protected function getAwsAccessKey()
    {
        if (true === is_null($this->awsAccessKey)) {
            $this->awsAccessKey = $this->getConfigValue('settings', 'aws_access_key');
        }
        return $this->awsAccessKey;
    }

    protected function getAwsSecretAccessKey()
    {
        if (true === is_null($this->awsSecretAccessKey)) {
            $this->awsSecretAccessKey = $this->getConfigValue('settings', 'aws_secret_access_key');
        }
        return $this->awsSecretAccessKey;
    }

    protected function getAwsRegion()
    {
        if (true == is_null($this->awsRegion)) {
            $this->awsRegion = $this->getConfigValue('settings', 'aws_region');
        }
        return $this->awsRegion;
    }

    protected function getProjectName()
    {
        if (true === is_null($this->projectName)) {
            $this->projectName = $this->getConfigValue('settings', 'project_name');
        }
        return $this->projectName;
    }

    protected function getRateLimit()
    {
        if (true === is_null($this->rateLimit)) {
            $this->rateLimit = $this->getConfigValue('rate_limit', 'rate_limit');
        }
        return $this->rateLimit;
    }

    protected function getBlockedCountryCodes()
    {
        if (true === empty($this->blockedCountryCodes)) {
            $blockedCountryCodes = $this->getConfigValue('blocked_countries', 'country_codes');
            if (false === empty($blockedCountryCodes)) {
                $this->blockedCountryCodes = $blockedCountryCodes;
            }
        }
        return $this->blockedCountryCodes;
    }

    protected function getBlockedIps()
    {
        if (true === empty($this->blockedIps)) {
            $blockedIps = $this->getConfigValue('blocked_ips', 'blocked_ips');
            $blockedIps = explode(PHP_EOL, $blockedIps);
            $blockedIps = array_filter(array_map('trim', $blockedIps));
            if (false === empty($blockedIps)) {
                $this->blockedIps = $blockedIps;
            }
        }
        return $this->blockedIps;
    }

    protected function getRateLimitWhitelistedIps()
    {
        if (true === empty($this->rateLimitWhitelistedIps)) {
            $rateLimitWhitelistedIps = $this->getConfigValue('rate_limit', 'whitelisted_ips');
            $rateLimitWhitelistedIps = explode(PHP_EOL, $rateLimitWhitelistedIps);
            $rateLimitWhitelistedIps = array_filter(array_map('trim', $rateLimitWhitelistedIps));
            if (false === empty($rateLimitWhitelistedIps)) {
                $this->rateLimitWhitelistedIps = $rateLimitWhitelistedIps;
            }
        }
        return $this->rateLimitWhitelistedIps;
    }

    protected function getBlockedBots()
    {
        if (true === empty($this->blockedBots)) {
            $blockedBots = $this->getConfigValue('blocked_bots', 'blocked_bots');
            $blockedBots = explode(PHP_EOL, $blockedBots);
            $blockedBots = array_filter(array_map('trim', $blockedBots));
            if (false === empty($blockedBots)) {
                $this->blockedBots = $blockedBots;
            }
        }
        return $this->blockedBots;
    }

    protected function getMagentoBackendWhitelistedIps()
    {
        if (true === empty($this->magentoBackendWhitelistedIps)) {
            $magentoBackendWhitelistedIps = $this->getConfigValue('magento_backend', 'whitelisted_ips');
            $magentoBackendWhitelistedIps = explode(PHP_EOL, $magentoBackendWhitelistedIps);
            $magentoBackendWhitelistedIps = array_filter(array_map('trim', $magentoBackendWhitelistedIps));
            if (false === empty($magentoBackendWhitelistedIps)) {
                $this->magentoBackendWhitelistedIps = $magentoBackendWhitelistedIps;
            }
        }
        return $this->magentoBackendWhitelistedIps;
    }

    protected function isMagentoBackendRestricted()
    {
        $configValue = $this->getConfigValue('magento_backend', 'is_enabled');
        $this->isMagentoBackendRestricted = ($configValue == self::MAGENTO_BACKEND_RESTRICTION_ENABLED ? true : false);
        return $this->isMagentoBackendRestricted;
    }

    protected function getWebAcl()
    {
        if (true === is_null($this->webAcl)) {
            $awsWaf = $this->getAwsWaf();
            $webAclName = $this->getWebAclName();
            $this->webAcl = $awsWaf->getWebAcl($webAclName);
        }
        return $this->webAcl;
    }

    protected function getWebAclName()
    {
        if (true === is_null($this->webAclName)) {
            $projectName = ucfirst($this->getProjectName());
            $this->webAclName = sprintf('%s-MGT-Web-ACL', $projectName);
        }
        return $this->webAclName;
    }

    protected function getWebAclRuleArrayIndex($webAclRuleName)
    {
        $webAcl = $this->getWebAcl();
        $webAclRules = $webAcl['Rules'] ?? [];
        $arrayIndex = array_search($webAclRuleName, array_column($webAclRules, 'Name'));
        if (false === is_null($arrayIndex) && true === isset($webAclRules[$arrayIndex])) {
            return $arrayIndex;
        } else {
            throw new \Exception(sprintf('Web ACL Rule "%s" not found.', $webAclRuleName));
        }
    }

    protected function getBackendFrontName()
    {
        $backendFrontName = $this->deploymentConfig->get(BackendConfigOptionsList::CONFIG_PATH_BACKEND_FRONTNAME);
        return $backendFrontName;
    }

    protected function getConfigValue($group, $field)
    {
        $configValue = '';
        if (true === isset($this->configData['groups'][$group]['fields'][$field]['value'])) {
            $configValue = $this->configData['groups'][$group]['fields'][$field]['value'];
            if (true === is_string($configValue)) {
                $configValue = trim($configValue);
            }
        }
        return $configValue;
    }

    protected function retry(callable $fn, $retries = 2, $delay = 3)
    {
        return Retry::retry($fn, $retries, $delay);
    }
}
