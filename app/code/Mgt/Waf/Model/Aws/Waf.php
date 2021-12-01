<?php

namespace Mgt\Waf\Model\Aws;

//$awsPharFile = sprintf('%s/app/code/Mgt/Waf/Phar/aws.phar', BP);
//require $awsPharFile;

use Aws\WAFV2\WAFV2Client as WafClient;
use Aws\Credentials\Credentials;
use Mgt\Waf\Model\Util\Retry;

class Waf
{
    const WEB_ACL_RULE_NAME_BLOCKED_COUNTRIES = 'Block-Countries';
    const WEB_ACL_RULE_NAME_RATE_LIMIT_IPV4 = 'Rate-Limit-IPv4';
    const WEB_ACL_RULE_NAME_RATE_LIMIT_IPV6 = 'Rate-Limit-IPv6';
    const WEB_ACL_RULE_BLOCK_MAGENTO_BACKEND_ACCESS = 'Block-Magento-Backend-Access';
    const WEB_ACL_RULE_ALLOW_MAGENTO_BACKEND_ACCESS_IPV4 = 'Allow-Magento-Backend-Access-IPv4';
    const WEB_ACL_RULE_ALLOW_MAGENTO_BACKEND_ACCESS_IPV6 = 'Allow-Magento-Backend-Access-IPv6';
    const IP_SET_BLOCKED_IPS_IPV4 = 'Blocked-IPs-IPv4';
    const IP_SET_BLOCKED_IPS_IPV6 = 'Blocked-IPs-IPv6';
    const IP_SET_RATE_LIMIT_WHITELISTED_IPV4 = 'Rate-Limit-Whitelisted-IPv4';
    const IP_SET_RATE_LIMIT_WHITELISTED_IPV6 = 'Rate-Limit-Whitelisted-IPv6';
    const IP_SET_MAGENTO_BACKEND_WHITELISTED_IPV4 = 'Magento-Backend-Whitelisted-IPv4';
    const IP_SET_MAGENTO_BACKEND_WHITELISTED_IPV6 = 'Magento-Backend-Whitelisted-IPv6';
    const REGEX_PATTERN_SET_BLOCKED_BOTS = 'Blocked-Bots';
    const SCOPE_REGIONAL = 'REGIONAL';

    protected $awsAccessKey;
    protected $awsSecretAccessKey;
    protected $awsRegion;
    protected $projectName;
    protected $wafClient;
    protected $credentials;
    protected $webAcls = [];
    protected $webAclCache = [];
    protected $ipSets = [];
    protected $regexPatternSets = [];

    public function __construct($awsAccessKey, $awsSecretAccessKey, $awsRegion, $projectName)
    {
        $this->awsAccessKey = $awsAccessKey;
        $this->awsSecretAccessKey = $awsSecretAccessKey;
        $this->awsRegion = $awsRegion;
        $this->projectName = $projectName;
    }

    public function getWafClient()
    {
        if (true === is_null($this->wafClient)) {
            $credentials = new Credentials($this->awsAccessKey, $this->awsSecretAccessKey);
            $this->wafClient = new WafClient([
                'version'     => 'latest',
                'region'      => $this->awsRegion,
                'credentials' => $credentials
            ]);
        }
        return $this->wafClient;
    }

    public function updateWebAcl(array $webAcl)
    {
        $wafClient = $this->getWafClient();
        $this->retry(function() use ($wafClient, $webAcl) {
            $webAcl['Scope'] = self::SCOPE_REGIONAL;
            $wafClient->updateWebACL($webAcl);
        });
    }

    public function updateIpSet($ipSetName, array $ips)
    {
        $ips = array_unique($ips);
        if (true === empty($ips)) {
            if ('v4' == substr($ipSetName, -2)) {
                $ips = ['52.28.149.157/32'];
            } else {
                $ips = ['2001:0db8:85a3:0000:0000:8a2e:0370:7334/128'];
            }
        }
        $ipSet = $this->getIpSet($ipSetName);
        $wafClient = $this->getWafClient();
        $this->retry(function() use ($wafClient, $ipSet, $ips) {
            $ipSetId = $ipSet['Id'] ?? '';
            $ipSetName = $ipSet['Name'] ?? '';
            $ipSetLockToken = $ipSet['LockToken'] ?? '';
            $ipSetDescription = $ipSet['Description'] ?? '';
            $wafClient->updateIPSet([
                'Id'          => $ipSetId,
                'Name'        => $ipSetName,
                'LockToken'   => $ipSetLockToken,
                'Description' => $ipSetDescription,
                'Addresses'   => $ips,
                'Scope'       => self::SCOPE_REGIONAL
            ]);
        });
    }

    public function updateBlockedBotsRegexPatternSet(array $bots)
    {
        $regexPatternSet = $this->getRegexPatternSet(self::REGEX_PATTERN_SET_BLOCKED_BOTS);
        $wafClient = $this->getWafClient();
        $regexString = sprintf('(?i)(%s)', implode('|', $bots));
        $this->retry(function() use ($wafClient, $regexPatternSet, $regexString) {
            $regexPatternSetId = $regexPatternSet['Id'];
            $regexPatternSetName = $regexPatternSet['Name'];
            $regexPatternSetDescription = $regexPatternSet['Description'];
            $regexPatternSetLockToken = $regexPatternSet['LockToken'];
            $wafClient->updateRegexPatternSet([
                'Id'                    => $regexPatternSetId,
                'Name'                  => $regexPatternSetName,
                'Description'           => $regexPatternSetDescription,
                'LockToken'             => $regexPatternSetLockToken,
                    'RegularExpressionList' => [
                        [
                            'RegexString' => $regexString
                        ]
                ],
                'Scope'                 => self::SCOPE_REGIONAL
            ]);
        });
    }

    public function getIpAddressesForIpSet($ipSetName)
    {
        $ipSet = $this->getIpSet($ipSetName);
        $ips = ((true === isset($ipSet['Addresses']) && false === empty($ipSet['Addresses'])) ? $ipSet['Addresses'] : []);
        return $ips;
    }

    public function getBlockedBots()
    {
        $bots = [];
        $regexPatternSet = $this->getRegexPatternSet(self::REGEX_PATTERN_SET_BLOCKED_BOTS);
        if (true === isset($regexPatternSet['RegularExpressionList'][0]['RegexString'])) {
            $regexString = $regexPatternSet['RegularExpressionList'][0]['RegexString'];
            $bots = explode('|', substr($regexString, 5, -1));
        }
        return $bots;
    }

    public function getWebAcls()
    {
        if (true === empty($this->webAcls)) {
            $wafClient = $this->getWafClient();
            $result = $this->retry(function() use ($wafClient) {
                $result = $wafClient->listWebACLs([
                    'Scope' => self::SCOPE_REGIONAL
                ]);
                return $result;
            });
            $webAcls = (array)$result->get('WebACLs');
            if (false === empty($webAcls)) {
                foreach ($webAcls as $webAcl) {
                    $this->webAcls[] = $webAcl;
                }
            }
        }
        return $this->webAcls;
    }

    public function getWebAcl($webAclName)
    {
        if (true === isset($this->webAclCache[$webAclName])) {
            return $this->webAclCache[$webAclName];
        } else {
            $webAcls = $this->getWebAcls();
            if (false === empty($webAcls)) {
                foreach ($webAcls as $webAcl) {
                    if (true === isset($webAcl['Name']) && $webAclName == $webAcl['Name']) {
                        $wafClient = $this->getWafClient();
                        $result = $this->retry(function() use ($wafClient, $webAcl) {
                            $webAclId = $webAcl['Id'] ?? '';
                            $webAclName = $webAcl['Name'] ?? '';
                            $result = $wafClient->getWebACL([
                                'Id'    => $webAclId,
                                'Name'  => $webAclName,
                                'Scope' => self::SCOPE_REGIONAL
                            ]);
                            return $result;
                        });
                        $webAclLockToken = $webAcl['LockToken'] ?? '';
                        $webAcl = (array)$result->get('WebACL');
                        $webAcl['LockToken'] = $webAclLockToken;
                        $this->webAclCache[$webAclName] = $webAcl;
                        return $this->webAclCache[$webAclName];
                    }
                }
            }
        }
        throw new \Exception(sprintf('Web ACL "%s". not found', $webAclName));
    }

    protected function getIpSets()
    {
        $wafClient = $this->getWafClient();
        $result = $this->retry(function() use ($wafClient) {
            $result = $wafClient->listIPSets([
                'Scope' => self::SCOPE_REGIONAL
            ]);
            return $result;
        });
        $ipSets = (array)$result->get('IPSets');
        if (false === empty($ipSets)) {
            $this->ipSets = $ipSets;
        }
        return $this->ipSets;
    }

    protected function getIpSet($ipSetName)
    {
        $ipSet = null;
        $ipSetName = $this->getIpSetName($ipSetName);
        $ipSets = $this->getIpSets();
        foreach ($ipSets as $wafIpSet) {
            $wafIpSetId = $wafIpSet['Id'] ?? '';
            $wafIpSetName = $wafIpSet['Name'] ?? '';
            $wafIpSetLockToken = $wafIpSet['LockToken'] ?? '';
            if (false === empty($wafIpSetName) && $wafIpSetName == $ipSetName) {
                $wafClient = $this->getWafClient();
                $result = $this->retry(function() use ($wafClient, $wafIpSetId, $wafIpSetName) {
                    $result = $wafClient->getIPSet([
                        'Id'    => $wafIpSetId,
                        'Name'  => $wafIpSetName,
                        'Scope' => self::SCOPE_REGIONAL
                    ]);
                    return $result;
                });
                $wafIpSet = (array)$result->get('IPSet');
                if (false === empty($wafIpSet)) {
                    $wafIpSet['LockToken'] = $wafIpSetLockToken;
                    $ipSet = $wafIpSet;
                    return $ipSet;
                }
                break;
            }
        }
        throw new \Exception(sprintf('IP Set "%s" not found.', $ipSetName));
    }

    protected function getRegexPatternSet($name)
    {
        $name = $this->getRegexPatternSetName($name);
        $regexPatternSets = $this->getRegexPatternSets();
        if (false === empty($regexPatternSets)) {
            foreach ($regexPatternSets as $regexPatternSet) {
                $regexPatternSetName = $regexPatternSet['Name'] ?? '';
                if (false === empty($regexPatternSetName) && $regexPatternSetName == $name) {
                    $wafClient = $this->getWafClient();
                    $result = $this->retry(function() use ($wafClient, $regexPatternSet) {
                        $regexPatternSetId = $regexPatternSet['Id'] ?? '';
                        $regexPatternSetName = $regexPatternSet['Name'] ?? '';
                        $result = $wafClient->getRegexPatternSet([
                            'Id'    => $regexPatternSetId,
                            'Name'  => $regexPatternSetName,
                            'Scope' => self::SCOPE_REGIONAL
                        ]);
                        return $result;
                    });
                    $data = $result->get('RegexPatternSet');
                    if (true === isset($data['RegularExpressionList'])) {
                        $regexPatternSet['RegularExpressionList'] = $data['RegularExpressionList'];
                    }
                    if (true === isset($data['LockToken'])) {
                        $regexPatternSet['LockToken'] = $data['LockToken'];
                    }
                    return $regexPatternSet;
                    break;
                }
            }
        }
        throw new \Exception(sprintf('Regex Pattern Set "%s" not found', $name));
    }

    protected function getRegexPatternSets()
    {
        $wafClient = $this->getWafClient();
        $result = $this->retry(function() use ($wafClient) {
            $result = $wafClient->listRegexPatternSets([
                'Scope' => self::SCOPE_REGIONAL
            ]);
            return $result;
        });
        $regexPatternSets = (array)$result->get('RegexPatternSets');
        if (false === empty($regexPatternSets)) {
            $this->regexPatternSets = $regexPatternSets;
        }
        return $this->regexPatternSets;
    }

    protected function getRegexPatternSetName($regexPatternSetName)
    {
        $projectName = ucfirst($this->getProjectName());
        $regexPatternSetName = sprintf('%s-MGT-%s', $projectName, $regexPatternSetName);
        return $regexPatternSetName;
    }

    public function getBlockedCountryCodes($webAclName)
    {
        $blockedCountryCodes = [];
        $webAcl = $this->getWebAcl($webAclName);
        $webAclRule = $this->getWebAclRule($webAcl, self::WEB_ACL_RULE_NAME_BLOCKED_COUNTRIES);
        if (true === isset($webAclRule['Statement']['GeoMatchStatement']['CountryCodes']) && false === empty($webAclRule['Statement']['GeoMatchStatement']['CountryCodes'])) {
            $blockedCountryCodes = $webAclRule['Statement']['GeoMatchStatement']['CountryCodes'];
        }
        return $blockedCountryCodes;
    }

    public function getWebAclRule(array $webAcl, $webAclRuleName)
    {
        $webAclRuleName = $this->getWebAclRuleName($webAclRuleName);
        $webAclRuleFound = false;
        $webAclRule = null;
        $webAclRules = $webAcl['Rules'] ?? [];
        if (false === empty($webAclRules)) {
            foreach ($webAclRules as $webAclRule) {
                if (true === isset($webAclRule['Name']) && $webAclRule['Name'] == $webAclRuleName) {
                    $webAclRuleFound = true;
                    break;
                }
            }
        }
        if (false === $webAclRuleFound) {
            throw new \Exception(sprintf('Web ACL Rule "%s" not found.', $webAclRuleName));
        } else {
            return $webAclRule;
        }
    }

    public function getRateLimit($webAclName)
    {
        $webAcl = $this->getWebAcl($webAclName);
        if (false === is_null($webAcl)) {
            $webbAclRuleName = $this->getWebAclRuleName(self::WEB_ACL_RULE_NAME_RATE_LIMIT_IPV4);
            $webAclRule = $this->getWebAclRule($webAcl, self::WEB_ACL_RULE_NAME_RATE_LIMIT_IPV4);
            if (false === is_null($webAclRule)) {
                $rateLimit = $webAclRule['Statement']['RateBasedStatement']['Limit'] ?? '';
                return $rateLimit;
            } else {
                throw new \Exception(sprintf('Web ACL Rule "%s" not found.', $webbAclRuleName));
            }
        } else {
            throw new \Exception(sprintf('Unable to get Web ACL "%s".', $webAclName));
        }
    }

    public function getWebAclRuleName($webAclRuleName)
    {
        $projectName = ucfirst($this->getProjectName());
        $webAclRuleName = sprintf('%s-MGT-%s', $projectName, $webAclRuleName);
        return $webAclRuleName;
    }

    public function getIpSetName($ipSetName)
    {
        $projectName = ucfirst($this->getProjectName());
        $ipSetName = sprintf('%s-MGT-%s', $projectName, $ipSetName);
        return $ipSetName;
    }

    protected function getProjectName()
    {
        return $this->projectName;
    }

    protected function retry(callable $fn, $retries = 2, $delay = 15)
    {
        return Retry::retry($fn, $retries, $delay);
    }
}