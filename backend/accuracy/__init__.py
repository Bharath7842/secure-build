"""The accuracy regression corpus: paired positive/negative/uncertain cases that
run the real scan graph offline against recorded LLM responses (SAST-00-070).

`case` loads a case, `replay_cache` replays/records its LLM responses, `runner`
scans a case and compares the persisted findings with what it expects. Used by
`tests/test_accuracy_corpus.py` and `scripts/accuracy/gate.py`; lives outside
`app/` because it is tooling, not part of the service.
"""
