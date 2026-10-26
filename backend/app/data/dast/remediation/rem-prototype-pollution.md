# Prototype pollution

## What it means

A key supplied under __proto__ or constructor.prototype showed up on the parsed object.

## How to fix it

Reject __proto__ and constructor keys. Use a parser that does not walk the prototype, and freeze Object.prototype.

## Verify

Repeat the JSON body and confirm the extra key is absent.
