<?php

namespace Mgt\Waf\Model\Config\BackendModel;

use Mgt\Waf\Model\Config\BackendModel\Value as ConfigValue;
use Mgt\Waf\Model\Aws\Waf as AwsWaf;

class BlockedBots extends ConfigValue
{
    protected function _afterLoad()
    {
        $sessionConfigData = $this->getSessionConfigData();
        $value = '';
        if (true === isset($sessionConfigData['groups']['blocked_bots']['fields']['blocked_bots']['value'])) {
            $value = $sessionConfigData['groups']['blocked_bots']['fields']['blocked_bots']['value'];
        } else {
            $awsAccessKey = $this->getAwsAccessKey();
            $projectName = $this->getProjectName();
            if (false === empty($awsAccessKey) && false === empty($projectName)) {
                $awsSecretAccessKey = $this->getAwsSecretAccessKey();
                $awsRegion = $this->getAwsRegion();
                $awsWaf = new AwsWaf($awsAccessKey, $awsSecretAccessKey, $awsRegion, $projectName);
                $bots = [];
                $blockedBots = $awsWaf->getBlockedBots();
                foreach ($blockedBots as $bot) {
                    if ($bot != 'mgt') {
                        $bots[] = $bot;
                    }
                }
                $value = implode(PHP_EOL, $bots);
            }
        }
        $this->setValue($value);
    }
}
