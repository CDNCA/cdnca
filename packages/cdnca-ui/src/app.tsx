// antd's <App> without its modal code in the first load.
// antd App calls Modal.useModal() at mount, which pulls Modal, Skeleton and
// rc-field-form (ContextIsolator) into every entry chunk although a page only
// needs them when it opens modal.confirm(). CdncaApp renders the same root
// (class names, App style, AppContext / AppConfigContext), so App.useApp()
// keeps working unchanged; modal.* loads antd's useModal on the first call
// and replays the call there. Once loaded, calls run synchronously as before.
import { lazy, Suspense, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ConfigProvider, message as antdMessage, notification as antdNotification, type AppProps } from 'antd'
import AppContext, { AppConfigContext, type useAppProps } from 'antd/es/app/context'
import useAppStyle from 'antd/es/app/style'
import type { HookAPI } from 'antd/es/modal/useModal'

type ModalType = keyof HookAPI
type ModalHandle = ReturnType<HookAPI[ModalType]>
type Requester = (run: (api: HookAPI) => void) => void

const modalTypes: ModalType[] = ['info', 'success', 'error', 'warning', 'confirm']

const ModalHost = lazy(() => import('antd/es/modal/useModal').then(({ default: useModal }) => ({
  default: function ModalHost({ onReady }: { onReady: (api: HookAPI) => void }) {
    const [api, holder] = useModal()
    // The holder has mounted (child effects run first), so patchElement works.
    useEffect(() => onReady(api), [api, onReady])
    return holder
  },
})))

function lazyModalApi(request: Requester): HookAPI {
  const open = (type: ModalType) => (config: Parameters<HookAPI[ModalType]>[0]) => {
    let real: ModalHandle | undefined
    const pending: ((handle: ModalHandle) => void)[] = []
    const run = (f: (handle: ModalHandle) => void) => { if (real) f(real); else pending.push(f) }
    request((api) => {
      real = api[type](config)
      pending.splice(0).forEach((f) => f(real!))
    })
    const handle: ModalHandle = {
      destroy: () => run((h) => h.destroy()),
      update: (next) => run((h) => h.update(next)),
      then: (resolve, reject) => new Promise((ok) => run((h) => ok(h.then(resolve, reject)))),
    }
    return handle
  }
  return Object.fromEntries(modalTypes.map((type) => [type, open(type)])) as unknown as HookAPI
}

/** App.useApp() of the nearest CdncaProvider without importing antd's App (first-load entries). */
export function useApp(): useAppProps {
  return useContext(AppContext)
}

export function CdncaApp({ className, message, notification, children }: Pick<AppProps, 'className' | 'message' | 'notification'> & { children: ReactNode }) {
  const { getPrefixCls } = useContext(ConfigProvider.ConfigContext)
  const prefixCls = getPrefixCls('app')
  const [wrapCSSVar, hashId, cssVarCls] = useAppStyle(prefixCls)
  const parentConfig = useContext(AppConfigContext)
  const appConfig = useMemo(() => ({
    message: { ...parentConfig.message, ...message },
    notification: { ...parentConfig.notification, ...notification },
  }), [message, notification, parentConfig.message, parentConfig.notification])
  const [messageApi, messageHolder] = antdMessage.useMessage(appConfig.message)
  const [notificationApi, notificationHolder] = antdNotification.useNotification(appConfig.notification)

  // Calls made before antd's useModal is loaded wait here and run once it is.
  const [hostWanted, setHostWanted] = useState(false)
  const realApi = useRef<HookAPI | null>(null)
  const queue = useRef<((api: HookAPI) => void)[]>([])
  const modalApi = useMemo(() => lazyModalApi((run) => {
    if (realApi.current) { run(realApi.current); return }
    queue.current.push(run)
    setHostWanted(true)
  }), [])
  const onReady = useMemo(() => (api: HookAPI) => {
    realApi.current = api
    queue.current.splice(0).forEach((run) => run(api))
  }, [])

  const value = useMemo(() => ({ message: messageApi, notification: notificationApi, modal: modalApi }), [messageApi, notificationApi, modalApi])
  const rootClass = [hashId, prefixCls, className, cssVarCls].filter(Boolean).join(' ')
  return wrapCSSVar(
    <AppContext.Provider value={value}>
      <AppConfigContext.Provider value={appConfig}>
        <div className={rootClass}>
          {hostWanted ? <Suspense fallback={null}><ModalHost onReady={onReady} /></Suspense> : null}
          {messageHolder}
          {notificationHolder}
          {children}
        </div>
      </AppConfigContext.Provider>
    </AppContext.Provider>,
  )
}
