<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Block\Adminhtml\Cache\Queue;

class Information extends \Magento\Backend\Block\Template
{
    /**
     * @var \Mgt\Varnish\Model\Cache\Config
     */
    protected $varnishConfig;

    /**
     * @var \Magento\Framework\App\Config
     */
    protected $config;

    /**
     * @param \Magento\Backend\Block\Template\Context $context
     * @param \Magento\Framework\App\Config $config
     * @param \Mgt\Varnish\Model\Cache\Config $varnishConfig
     * @param array $data
     * @SuppressWarnings(PHPMD.ExcessiveParameterList)
     */
    public function __construct(
        \Magento\Backend\Block\Template\Context $context,
        \Magento\Framework\App\Config $config,
        \Mgt\Varnish\Model\Cache\Config $varnishConfig,
        array $data = []
    ) {
        parent::__construct($context, $data);
        $this->config = $config;
        $this->varnishConfig = $varnishConfig;
    }

    public function isCacheWarmerEnabled()
    {
        $isCacheWarmerEnabled = $this->varnishConfig->isCacheWarmerEnabled();
        return $isCacheWarmerEnabled;
    }

    public function getQueueInformationAjaxUrl()
    {
        $queueInformationAjaxUrl = $this->getUrl('mgtvarnish/queue/information');
        return $queueInformationAjaxUrl;
    }
}