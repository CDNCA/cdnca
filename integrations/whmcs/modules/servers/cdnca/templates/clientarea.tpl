{* CDNCA CDN 客户区概览（cdnca_ClientArea → tabOverviewModuleOutputTemplate，追加在 WHMCS 原生概览（价格、账单）下方） *}
<div class="card mb-3 cdnca-overview">
    <div class="card-body">
        <h3 class="card-title h5">CDN 服务</h3>
        {if $cdnca_ok}
            <dl class="row mb-3">
                <dt class="col-sm-4">套餐</dt>
                <dd class="col-sm-8">{$cdnca_product|escape} {if $cdnca_period}<span class="text-muted">（{$cdnca_period|escape}）</span>{/if}</dd>
                <dt class="col-sm-4">状态</dt>
                <dd class="col-sm-8">{$cdnca_status|escape}</dd>
                <dt class="col-sm-4">到期时间</dt>
                <dd class="col-sm-8">{$cdnca_ends_at|escape}</dd>
                <dt class="col-sm-4">CDN 用户名</dt>
                <dd class="col-sm-8">{$cdnca_username|escape}</dd>
                <dt class="col-sm-4">本周期流量</dt>
                <dd class="col-sm-8">{$cdnca_traffic|escape}{if $cdnca_usage_window} <span class="text-muted small">（{$cdnca_usage_window|escape}）</span>{/if}</dd>
            </dl>
            {if $cdnca_can_login}
                <form method="post" action="clientarea.php?action=productdetails&amp;id={$cdnca_serviceid}" target="_blank">
                    <input type="hidden" name="token" value="{$token}">
                    <input type="hidden" name="dosinglesignon" value="1">
                    <button type="submit" class="btn btn-primary">登录 CDN 控制台</button>
                </form>
            {else}
                <p class="text-muted mb-0">服务当前不可登录（{$cdnca_status|escape}）。</p>
            {/if}
        {else}
            <div class="alert alert-warning mb-0" role="alert">暂时无法读取 CDN 服务信息：{$cdnca_error|escape}</div>
        {/if}
    </div>
</div>
