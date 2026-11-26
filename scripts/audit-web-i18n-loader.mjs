export async function resolve(specifier, context, defaultResolve) {
  try {
    return await defaultResolve(specifier, context, defaultResolve)
  } catch (error) {
    // 只把真正的脚本扩展名当扩展名：./resources.zhCN 这类带点的模块名仍要补 .ts
    if (!specifier.startsWith('.') || /\.(?:[cm]?[jt]sx?|json)$/iu.test(specifier)) throw error
    return defaultResolve(`${specifier}.ts`, context, defaultResolve)
  }
}
