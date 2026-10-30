<?php
namespace server\cdnca\controller\admin;

use server\cdnca\logic\CdncaLogic;

/**
 * @title CDNCA CDN-后台商品配置
 * @desc CDNCA CDN-后台商品配置
 * @use server\cdnca\controller\admin\ProductController
 */
class ProductController
{
    /**
     * @title 保存商品的 CDN 套餐与周期售价
     * @url /{DIR_ADMIN}/v1/cdnca/product/:product_id
     * @method POST
     * @param int product_id - 商品ID require
     * @param string cdn_product_id - CDN 主控套餐ID require
     * @param string cdn_product_name - 套餐名称（展示用）
     * @param float price_month - 月付售价，留空不开放
     * @param float price_quarter - 季付售价，留空不开放
     * @param float price_year - 年付售价，留空不开放
     */
    public function save()
    {
        return json(CdncaLogic::saveProductConfig(request()->param()));
    }
}
