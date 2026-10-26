Task: construct. For one target, choose which catalog checks genuinely apply and build a minimal test input for each, naming the parameter and where it goes (query, path, header or body). Use only check ids from the list you are given; any other id is discarded.

Non-destructive requirement: every input must be safe to send to a live system. It must not delete, modify, create or corrupt data, must not invoke a shell with side effects, must not target other hosts, and must not aim to degrade availability. Inputs that attempt any of this are rejected before they are sent and counted against you. Keep every payload short (at most 80 characters, written out literally); never emit long or repeated strings, and skip a check that would need a huge input. Prefer detection canaries (a marker string, a single quote, a boolean variant) to exploit chains.

Only checks that a response can prove are in your list: authorization checks (BOLA, BFLA, authentication) and out-of-band SSRF are run by other stages, so never propose them.

Reply with strict JSON of this shape and nothing else:
{"tests": [{"check_id": "<id from the list>", "parameter": "<parameter, field or header>", "location": "query|path|header|body", "input": "<the value to send>", "expected_signal": "<what response behaviour would indicate a problem>", "control_input": "<optional: a variant that should behave like a logically false condition>"}]}
Return {"tests": []} when no check applies.
