<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Controller\Api;

class PurgeUrl extends \Magento\Framework\App\Action\Action
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
     * Purges a single url
     *
     */
    public function execute()
    {
        $request = $this->getRequest();
        $response = $this->getResponse();
        $body = [];
        $secretKey = $request->getParam('secretKey');
        $url = $request->getParam('url');
        if ($secretKey && $url) {
            try {
                $apiSecretKey = $this->config->getApiSecretKey();
                if ($secretKey != $apiSecretKey) {
                    throw new \Exception('Secret api key is not correct');
                }
                $this->cachePurger->purgeUrlRequest($url);
                $body = [
                    'success' => 1,
                    'message' => sprintf('The URL "%s" has been purged.', $url)
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
