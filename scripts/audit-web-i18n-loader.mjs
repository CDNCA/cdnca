export async function resolve(specifier, context, defaultResolve) {
  try {
    return await defaultResolve(specifier, context, defaultResolve)
  } catch (error) {
    if (!specifier.startsWith('.') || /\.[a-z]+$/iu.test(specifier)) throw error
    return defaultResolve(`${specifier}.ts`, context, defaultResolve)
  }
}
