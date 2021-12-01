<?php

namespace Mgt\Waf\Model\Config\BackendModel;

use Mgt\Waf\Model\Config\BackendModel\Value as ConfigValue;
use Mgt\Waf\Model\Aws\Waf as AwsWaf;

class RateLimit extends ConfigValue
{
    protected function _afterLoad()
    {
        $sessionConfigData = $this->getSessionConfigData();
        $value = (string)$this->getValue();
        if (true === isset($sessionConfigData['groups']['rate_limit']['fields']['rate_limit']['value'])) {
            $value = $sessionConfigData['groups']['rate_limit']['fields']['rate_limit']['value'];
        } else {
            $awsAccessKey = $this->getAwsAccessKey();
            $projectName = $this->getProjectName();
            if (false === empty($awsAccessKey) && false === empty($projectName)) {
                $awsSecretAccessKey = $this->getAwsSecretAccessKey();
                $awsRegion = $this->getAwsRegion();
                $webAclName = $this->getWebAclName();
                $awsWaf = new AwsWaf($awsAccessKey, $awsSecretAccessKey, $awsRegion, $projectName);
                $value = $awsWaf->getRateLimit($webAclName);
            }
        }
        $this->setValue($value);
    }
}
