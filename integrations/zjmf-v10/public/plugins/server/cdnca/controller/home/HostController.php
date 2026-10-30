<?php
namespace server\cdnca\controller\home;

use server\cdnca\logic\CdncaLogic;

/**
 * @title CDNCA CDN-前台
 * @desc CDNCA CDN-前台
 * @use server\cdnca\controller\home\HostController
 */
class HostController
{
    /**
     * @title 免密登录 CDN 控制台
     * @desc 校验产品属于当前登录客户后，向 CDN 主控申请一次性登录链接（60 秒、只能用一次）
     * @url /console/v1/cdnca/host/:id/sso
     * @method POST
     * @param int id - 产品ID require
     * @return string data.url - 一次性登录链接
     */
    public function sso()
    {
        $param = request()->param();
        // get_client_id() 读 CheckHome 写入的 request()->client_id；子账号钩子会换成主账号 ID。
        return json(CdncaLogic::ssoForClient(isset($param['id']) ? (int)$param['id'] : 0, (int)get_client_id()));
    }
}
