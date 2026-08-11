import { defineConfig } from 'vitepress'

// Docs site for Toamaisutaa, built from the markdown in this folder. Served at the domain root on
// Cloudflare Pages, so no `base` is needed. Build: `vitepress build` (output: .vitepress/dist).
export default defineConfig({
  title: 'Toamaisutaa',
  description: 'Authentication for ASP.NET Core: OIDC bearer validation, optional local password login, and its own EF Core migrations.',
  lastUpdated: true,
  cleanUrls: true,
  // README-style links elsewhere point at "docs/*.md"; inside the site links resolve fine, but keep
  // the build from failing on the odd absolute/anchor link.
  ignoreDeadLinks: true,
  head: [
    ['link', { rel: 'icon', href: '/favicon.svg' }],
    ['meta', { property: 'og:image', content: '/wordmark.png' }],
  ],
  themeConfig: {
    nav: [
      { text: 'Intro', link: '/intro' },
      { text: 'Getting started', link: '/getting-started' },
      { text: 'OIDC', link: '/oidc' },
      { text: 'Password login', link: '/password-login' },
      { text: 'Development', link: '/dev-setup' },
    ],
    sidebar: [
      { text: 'What is Toamaisutaa?', link: '/intro' },
      {
        text: 'Setup',
        collapsed: false,
        items: [
          { text: 'Getting started', link: '/getting-started' },
          { text: 'Storage and migrations', link: '/storage' },
        ],
      },
      {
        text: 'Signing in',
        collapsed: false,
        items: [
          { text: 'OIDC bearer validation', link: '/oidc' },
          { text: 'Local password login', link: '/password-login' },
        ],
      },
      {
        text: 'Development',
        collapsed: false,
        items: [
          { text: 'Developer setup', link: '/dev-setup' },
        ],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/PianoNic/Toamaisutaa' },
    ],
    search: { provider: 'local' },
    editLink: {
      pattern: 'https://github.com/PianoNic/Toamaisutaa/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
    footer: {
      message: 'Made with care by PianoNic.',
      copyright: 'Toamaisutaa',
    },
  },
})
