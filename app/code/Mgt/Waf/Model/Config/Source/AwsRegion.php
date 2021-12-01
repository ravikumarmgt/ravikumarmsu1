<?php

namespace Mgt\Waf\Model\Config\Source;

class AwsRegion implements \Magento\Framework\Option\ArrayInterface
{
    static protected $awsRegions = [
        'us-east-1'      => 'US East (N. Virginia)',
        'us-east-2'      => 'US East (Ohio)',
        'us-west-2'      => 'US West (Oregon)',
        'us-west-1'      => 'US West (N. California)',
        'ca-central-1'   => 'Canada (Central)',
        'eu-west-1'      => 'EU (Ireland)',
        'eu-central-1'   => 'EU (Frankfurt)',
        'eu-west-2'      => 'EU (London)',
        'eu-west-3'      => 'EU (Paris)',
        'eu-north-1'     => 'EU (Stockholm)',
        'me-south-1'     => 'Middle East (Bahrain)',
        'ap-southeast-1' => 'Asia Pacific (Singapore)',
        'ap-northeast-1' => 'Asia Pacific (Toyko)',
        'ap-east-1'      => 'Asia Pacific (Hong Kong)',
        'ap-southeast-2' => 'Asia Pacific (Sydney)',
        'ap-northeast-2' => 'Asia Pacific (Seoul)',
        'ap-south-1'     => 'Asia Pacific (Mumbai)',
        'sa-east-1'      => 'South America (Sao Paulo)'
    ];

    public function toOptionArray()
    {
        $optionArray = [];
        foreach (self::$awsRegions as $awsRegion => $awsRegionName) {
            $optionArray[] = [
                'value' => $awsRegion,
                'label' => $awsRegionName
            ];
        }
        return $optionArray;
    }

    public function toArray()
    {
        $toArray = [];
        foreach (self::$awsRegions as $awsRegion => $awsRegionName) {
            $toArray[$awsRegion] = $awsRegionName;
        }
        return $toArray;
    }
}