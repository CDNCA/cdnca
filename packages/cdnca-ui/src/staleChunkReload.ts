// 发版后旧分块失效时整页刷新一次（不依赖 antd，入口可直接用；auth-fe-perf 从 staleChunk.tsx 拆出）。
export function isStaleChunkError(error: unknown): boolean {
  const message = error instanceof Error ? `${error.name} ${error.message}` : String(error)
  return /ChunkLoadError|Loading (?:chunk|CSS chunk)|dynamically imported module|importing a module script failed|unable to preload CSS/i.test(message)
}

const reloadStorageKey = 'cdnca:stale-chunk-reload'
// 标记只在 30 秒内有效：刷新后新页面马上又失败（新版本也缺分块）才拦住防循环；
// 同一标签页以后再遇到发版，仍会自动刷新一次。
const reloadLoopWindowMs = 30_000
let reloading = false

function markReloadAttempt(): boolean {
  try {
    const last = Number(window.sessionStorage.getItem(reloadStorageKey))
    if (last && Date.now() - last < reloadLoopWindowMs) return false
    window.sessionStorage.setItem(reloadStorageKey, String(Date.now()))
    return true
  } catch {
    return false
  }
}

// 同一页面生命周期只刷新一次；返回 true 表示已在刷新。
export function reloadForStaleChunk(reload: () => void = () => window.location.reload()): boolean {
  if (reloading) return true
  if (!markReloadAttempt()) return false
  reloading = true
  reload()
  return true
}

// 仅测试用：模拟新的一次整页加载。
export function resetStaleChunkReloadForTest(): void {
  reloading = false
}
