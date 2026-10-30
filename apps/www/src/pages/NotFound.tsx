export function NotFoundPage() {
  return (
    <section className="section container narrow">
      <h1>页面不存在 <span lang="en">/ Page not found</span></h1>
      <p>你访问的地址不存在或已移动。<span lang="en">The page you requested does not exist.</span></p>
      <p><a className="btn btn-primary" href="/">返回首页</a> <a className="btn btn-ghost" href="/en/" lang="en">Home (English)</a></p>
    </section>
  )
}
