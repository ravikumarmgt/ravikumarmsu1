<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\Cache\ResourceModel\Grid;

class Collection extends \Magento\Backend\Model\Cache\ResourceModel\Grid\Collection
{
    /**
     * @param \Magento\Framework\Data\Collection\EntityFactory $entityFactory
     * @param \Magento\Framework\App\Cache\TypeListInterface $cacheTypeList
     */
    public function __construct(
        \Magento\Framework\Data\Collection\EntityFactory $entityFactory,
        \Magento\Framework\App\Cache\TypeListInterface $cacheTypeList
    ) {
        parent::__construct($entityFactory, $cacheTypeList);
    }

    /**
     * Load data
     *
     * @param bool $printQuery
     * @param bool $logQuery
     * @return $this
     * @SuppressWarnings(PHPMD.UnusedFormalParameter)
     */
    public function loadData($printQuery = false, $logQuery = false)
    {
        if (!$this->isLoaded()) {
            $cacheTypes = $this->_cacheTypeList->getTypes();
            $cacheTypes = $this->prepareCacheTypes($cacheTypes);
            foreach ($cacheTypes as $type) {
                $this->addItem($type);
            }
            $this->_setIsLoaded(true);
        }
        return $this;
    }

    protected function prepareCacheTypes(array $cacheTypes)
    {
        $cacheTypes['full_page']->setCacheType('MGT Varnish Cache');
        $cacheTypes['full_page']->setDescription('Varnish Cache provided by MGT-COMMERCE');
        return $cacheTypes;
    }
}