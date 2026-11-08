# Enkidu Security Writeups

A Markdown-first repository for technical writeups published on Arman Mishra's portfolio at https://enkidudev.github.io/.

## Suggested structure

```text
security-writeups/
├── articles/
│   ├── ad-kerberos-notes.md
│   └── web-testing-notes.md
├── templates/
│   └── ARTICLE_TEMPLATE.md
└── .github/
    └── workflows/
        └── notify-portfolio.yml
```

## Publish an article

1. Copy `templates/ARTICLE_TEMPLATE.md` into `articles/`.
2. Give it a descriptive filename.
3. Fill in the frontmatter and article body.
4. Set `published: true` only when the article is ready for public release.
5. Commit and push to `main`.

The portfolio will fetch the latest repository content, generate the writeup listing and individual article pages, assign the next chronological `WR-###` ID, and deploy.

## Required repository secret

In this repository, open **Settings → Secrets and variables → Actions** and add:

`PORTFOLIO_DISPATCH_TOKEN`

Use a fine-grained personal access token with **Contents: Read and write** access to the portfolio repository `enkidudev/enkidudev.github.io`.

This token lets the workflow send a `repository_dispatch` event to the portfolio repository. The portfolio's own workflow then fetches the latest writeups and rebuilds the website.

## Portfolio repository configuration

The portfolio workflow is configured for this exact repository: `enkidudev/security-writeups`. The portfolio repository is `enkidudev/enkidudev.github.io`.

Recommended: make this repository public because the articles are intended for a public portfolio. A public repository needs no read token. If you keep it private, add a separate read-only token as `WRITEUPS_REPO_READ_TOKEN` in the portfolio repository.

## Images and attachments

Keep an article's images beside the Markdown file or in an adjacent folder, and use relative Markdown image paths. Avoid committing sensitive screenshots, credentials, customer data, private reports, or unpublished bounty details.
