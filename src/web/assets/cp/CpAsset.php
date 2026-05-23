<?php

namespace modules\actionmfa\web\assets\cp;

use craft\web\AssetBundle;
use craft\web\assets\cp\CpAsset as CraftCpAsset;

class CpAsset extends AssetBundle
{
    public $publishOptions = ['forceCopy' => true];

    public function init(): void
    {
        $this->sourcePath = __DIR__;
        $this->depends = [CraftCpAsset::class];
        $this->js = ['action-mfa.js'];
        $this->css = ['action-mfa.css'];
        parent::init();
    }
}
