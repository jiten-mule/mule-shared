# @mule/shared

Design tokens, base styles, session and Google ID-token verification, shared
by desk, bench and table.

Table installs it as `"@mule/shared": "file:../mule-desk/shared"` for local
work. npm cannot install a git sub-folder, so before deploy either publish
this folder as a package (GitHub Packages) or give it its own repo, and point
table at that git URL. Decision for Jiten.

Not yet wired into desk itself: desk's `src/styles.css` and
`netlify/functions/_lib/{session,google}.mjs` still hold their own copies.
Switching desk and bench to import from here is the follow-up that stops
the copies drifting.
