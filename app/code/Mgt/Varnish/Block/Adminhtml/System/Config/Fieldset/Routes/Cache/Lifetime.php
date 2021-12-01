<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Block\Adminhtml\System\Config\Fieldset\Routes\Cache;

class Lifetime extends \Magento\Config\Block\System\Config\Form\Field\FieldArray\AbstractFieldArray
{
    /**
     * @var \Magento\Framework\Data\Form\Element\Factory
     */
    protected $_elementFactory;

    /**
     * @param \Magento\Backend\Block\Template\Context $context
     * @param \Magento\Framework\Data\Form\Element\Factory $elementFactory
     * @param array $data
     */
    public function __construct(
        \Magento\Backend\Block\Template\Context $context,
        \Magento\Framework\Data\Form\Element\Factory $elementFactory,
        array $data = []
    )
    {
        $this->_elementFactory  = $elementFactory;
        parent::__construct($context,$data);
    }

    protected function _construct()
    {
        $this->addColumn('field1', ['label' => __('Route')]);
        $this->addColumn('field2', ['label' => __('Cache Lifetime')]);
        $this->addColumn('field3', ['label' => __('Comment')]);
        $this->_addAfter = false;
        $this->_addButtonLabel = __('Add');
        parent::_construct();
    }

    public function getArrayRows()
    {
        $element = $this->getElement();
        $elementValue = $element->getValue();
        $unserializedValue = @unserialize($elementValue);
        if ($elementValue === 'b:0;' || $unserializedValue !== false) {
            $element->setValue($unserializedValue);
        }
        return parent::getArrayRows();
    }
}