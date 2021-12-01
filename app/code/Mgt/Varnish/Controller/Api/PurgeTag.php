<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Controller\Api;

class PurgeTag extends \Magento\Framework\App\Action\Action
{
     /**
     * @var \Magento\CacheInvalidate\Model\PurgeCache
     */
    protected $cachePurger;

    /**
     * @var \Mgt\Varnish\Model\Cache\Config
     */
    protected $config;

    /**
     * @param \Magento\Framework\App\Action\Context $context
     * @param \Magento\CacheInvalidate\Model\PurgeCache $cachePurger
     * @param \Mgt\Varnish\Model\Cache\Config $config
     */
    public function __construct(
        \Magento\Framework\App\Action\Context $context,
        \Magento\CacheInvalidate\Model\PurgeCache $cachePurger,
        \Mgt\Varnish\Model\Cache\Config $config
    ) {
        $this->cachePurger = $cachePurger;
        $this->config = $config;
        parent::__construct($context);
    }
    
    /**
     * Purges a single tag
     *
     */
    public function execute()
    {
        $request = $this->getRequest();
        $response = $this->getResponse();
        $body = [];
        $secretKey = $request->getParam('secretKey');
        $tag = $request->getParam('tag');
        if ($secretKey && $tag) {
            try {
                $apiSecretKey = $this->config->getApiSecretKey();
                if ($secretKey != $apiSecretKey) {
                    throw new \Exception('Secret api key is not correct');
                }
                $tags = [$tag];
                $this->cachePurger->sendPurgeRequest($tags);
                $body = [
                    'success' => 1,
                    'message' => sprintf('Varnish Cache purged by following tag: %s', $tag)
                ];
            } catch (\Exception $e) {
                $errorMessage = $e->getMessage();
                $body = [
                    'success' => 0,
                    'message' => $errorMessage
                ];
            }
        }
        $body = json_encode($body);
        $response->setHeader('Content-Type', 'application/json');
        $response->setBody($body);
        $response->sendResponse();
        exit;
    }
}
