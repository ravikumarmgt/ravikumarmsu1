<?php

namespace Mgt\Waf\Model\Config\BackendModel;

use Mgt\Waf\Model\Config\BackendModel\Value as ConfigValue;
use Mgt\Waf\Model\Aws\Waf as AwsWaf;

class BlockedCountries extends ConfigValue
{
    protected function _afterLoad()
    {
        $sessionConfigData = $this->getSessionConfigData();
        $value = '';
        if (true === isset($sessionConfigData['groups']['blocked_countries']['fields']['country_codes']['value'])) {
            $value = $sessionConfigData['groups']['blocked_countries']['fields']['country_codes']['value'];
        } else {
            $awsAccessKey = $this->getAwsAccessKey();
            $projectName = $this->getProjectName();
            if (false === empty($awsAccessKey) && false === empty($projectName)) {
                $awsSecretAccessKey = $this->getAwsSecretAccessKey();
                $awsRegion = $this->getAwsRegion();
                $webAclName = $this->getWebAclName();
                $awsWaf = new AwsWaf($awsAccessKey, $awsSecretAccessKey, $awsRegion, $projectName);
                $blockedCountryCodes = $awsWaf->getBlockedCountryCodes($webAclName);
                if (false === empty($blockedCountryCodes)) {
                    $value = implode(',', $blockedCountryCodes);
                }
            }
        }
        $this->setValue($value);
    }
}
