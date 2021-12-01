<?php

namespace Mgt\Waf\Model\Config\BackendModel;

class Value extends \Magento\Framework\App\Config\Value
{
    const MGT_WAF_CONFIG_DATA = 'mgtWafConfigData';

    protected $awsAccessKey;
    protected $awsSecretAccessKey;
    protected $awsRegion;
    protected $projectName;
    protected $webAclName;
    protected $session;

    /**
     * @param \Magento\Backend\Model\Session $session
     * @param \Magento\Framework\Model\Context $context
     * @param \Magento\Framework\Registry $registry
     * @param \Magento\Framework\App\Config\ScopeConfigInterface $config
     * @param \Magento\Framework\App\Cache\TypeListInterface $cacheTypeList
     * @param \Magento\Framework\Model\ResourceModel\AbstractResource|null $resource
     * @param \Magento\Framework\Data\Collection\AbstractDb|null $resourceCollection
     * @param array $data
     */
    public function __construct(
        \Magento\Backend\Model\Session $session,
        \Magento\Framework\Model\Context $context,
        \Magento\Framework\Registry $registry,
        \Magento\Framework\App\Config\ScopeConfigInterface $config,
        \Magento\Framework\App\Cache\TypeListInterface $cacheTypeList,
        \Magento\Framework\Model\ResourceModel\AbstractResource $resource = null,
        \Magento\Framework\Data\Collection\AbstractDb $resourceCollection = null,
        array $data = []
    ) {
        $this->session = $session;
        parent::__construct($context, $registry, $config, $cacheTypeList, $resource, $resourceCollection, $data);
    }

    protected function getAwsAccessKey()
    {
        if (true === is_null($this->awsAccessKey)) {
            $this->awsAccessKey = $this->getConfigValue('mgt_waf/settings/aws_access_key');
        }
        return $this->awsAccessKey;
    }

    protected function getAwsSecretAccessKey()
    {
        if (true === is_null($this->awsSecretAccessKey)) {
            $this->awsSecretAccessKey = $this->getConfigValue('mgt_waf/settings/aws_secret_access_key');
        }
        return $this->awsSecretAccessKey;
    }

    protected function getAwsRegion()
    {
        if (true == is_null($this->awsRegion)) {
            $this->awsRegion = $this->getConfigValue('mgt_waf/settings/aws_region');
        }
        return $this->awsRegion;
    }

    protected function getProjectName()
    {
        if (true === is_null($this->projectName)) {
            $this->projectName = $this->getConfigValue('mgt_waf/settings/project_name');
        }
        return $this->projectName;
    }

    protected function getWebAclName()
    {
        if (true === is_null($this->webAclName)) {
            $projectName = ucfirst($this->getProjectName());
            $this->webAclName = sprintf('%s-MGT-Web-ACL', $projectName);
        }
        return $this->webAclName;
    }

    protected function getSessionConfigData()
    {
        $session = $this->getSession();
        $sessionConfigData = $session->getData(self::MGT_WAF_CONFIG_DATA);
        return $sessionConfigData;
    }

    protected function getSession()
    {
        return $this->session;
    }

    protected function getConfigValue($path)
    {
        return $this->_config->getValue($path);
    }
}
