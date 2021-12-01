<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\Observer;

use Magento\Framework\Event\ObserverInterface;
use Magento\Framework\Event\Observer;

class PredispatchAdminActionControllerObserver implements ObserverInterface
{
    /**
     * @var \Mgt\Varnish\Model\Feed\Feed
     */
    protected $feed;

    /**
     * @var \Magento\Backend\Model\Auth\Session
     */
    protected $backendAuthSession;

    /**
     * @param \Mgt\Varnish\Model\Feed\Feed $feed
     * @param \Magento\Backend\Model\Auth\Session $backendAuthSession
     */
    public function __construct(
        \Mgt\Varnish\Model\Feed\Feed $feed,
        \Magento\Backend\Model\Auth\Session $backendAuthSession
    ) {
        $this->feed = $feed;
        $this->backendAuthSession = $backendAuthSession;
    }

    /**
     * Predispath admin action controller
     *
     * @param \Magento\Framework\Event\Observer $observer
     */
    public function execute(Observer $observer)
    {
        if (true === $this->backendAuthSession->isLoggedIn()) {
            $this->feed->checkUpdate();
        }
    }
}
