# Stored cross-site scripting

## What it means

A value the scan submitted was saved and later rendered as live markup. Anyone who opens that page runs the markup.

## How to fix it

- Escape the value on output for the context it is rendered in, using the framework's templating defaults.
- Do not insert stored text with innerHTML or a raw HTML binding.
- Add a Content-Security-Policy that blocks inline script, as a second layer.

## Verify

Delete the scan's marker from the stored record (each marker is unique to the scan), re-run, and confirm it is no longer rendered as markup.
