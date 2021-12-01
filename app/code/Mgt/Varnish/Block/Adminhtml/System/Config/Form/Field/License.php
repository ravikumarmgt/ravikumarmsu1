<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Block\Adminhtml\System\Config\Form\Field;

class License extends \Magento\Config\Block\System\Config\Form\Field
{
    /**
     * @var \Mgt\Varnish\Model\License
     */
    protected $license;

    /**
     * @param \Magento\Backend\Block\Template\Context $context
     * @param \Mgt\Varnish\Model\License $license
     * @param array $data
     */
    public function __construct(
        \Magento\Backend\Block\Template\Context $context,
        \Mgt\Varnish\Model\License $license,
        array $data = []
    )
    {
        $this->license  = $license;
        parent::__construct($context, $data);
    }
    /**
     * Retrieve HTML markup for given form element
     *
     * @param \Magento\Framework\Data\Form\Element\AbstractElement $element
     * @return string
     */
    public function render(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {
        $isCheckboxRequired = $this->_isInheritCheckboxRequired($element);

        // Disable element if value is inherited from other scope. Flag has to be set before the value is rendered.
        if ($element->getInherit() == 1 && $isCheckboxRequired) {
            $element->setDisabled(true);
        }

        $html = '<td class="label"><label for="' .
            $element->getHtmlId() . '"><span' .
            $this->_renderScopeLabel($element) . '>' .
            $element->getLabel() .
            '</span></label></td>';
        $html .= $this->_renderValue($element);

        $html .= $this->_renderHint($element);

        return $this->_decorateRowHtml($element, $html);
    }

    protected function _renderValue(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {
        $html = '<td class="value">';

        $licensedDomains = $this->license->getDomains();
        if ($licensedDomains) {
            $html .= implode('<br>', $licensedDomains);
        }

        if ($element->getComment()) {
            $html .= '<p class="note"><span>' . $element->getComment() . '</span></p>';
        }
        $html .= '</td>';
        return $html;
    }
}