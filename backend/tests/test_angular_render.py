"""Angular render-context continuation (SAST-03-080): a translation value or a
component property is followed to where its template renders it.

A small app is written to a temp directory per test; findings go through the
real hook (`prepare_findings`), so rule ids, CWE scoping and the precedence
against a model verdict are exercised too.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_typescript")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("boto3", reason="pipeline modules import llm_client")

_ENGINE = Path(__file__).resolve().parents[1] / "sast_engine"
if str(_ENGINE) not in sys.path:
    sys.path.insert(0, str(_ENGINE))

import ast_struct  # noqa: E402
from pipeline import angular_render as ar, finding_facts  # noqa: E402
from pipeline.validators import VALIDATOR_CONTEXT_USAGE_KEY, ValidatorContext  # noqa: E402

pytestmark = pytest.mark.unit

TS_HEAD = """import { Component } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';

"""


def _component(name, template_ref, body, extra_imports=""):
    return (TS_HEAD + extra_imports
            + f"@Component({{ selector: 'app-{name}', {template_ref} }})\n"
            + f"export class {name.title()}Component {{\n"
            + "  constructor(private translate: TranslateService) {}\n" + body + "}\n")


def _write(root, rel, text):
    f = root / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)


def _decide(root, rel, needle, *, cwe="CWE-79", rule_id="llm-extra", verdict="true_positive"):
    text = (root / rel).read_text()
    line = next(i for i, l in enumerate(text.splitlines(), 1) if needle in l)
    f = {"file_path": rel, "line": line, "rule_id": rule_id, "cwe": cwe, "kind": "llm", "verdict": verdict,
         "verdict_reason": "The model says so.", "issue_class": "security", "confidence": 0.8}
    ctx = ValidatorContext(repo_root=root)
    finding_facts.prepare_findings([f], text, file_path=rel, usage={VALIDATOR_CONTEXT_USAGE_KEY: ctx})
    mine = [(o["outcome"], o.get("reason_tag")) for o in (f.get("facts") or {}).get("validators", [])
            if o["validator"] == "angular_render_context"]
    return f, mine


def test_component_metadata_reads_template_url_and_inline_template():
    meta = ast_struct.component_metadata(
        "@Component({ selector: 'a', templateUrl: './a.html' })\nexport class A {}\n"
        "@Component({ selector: 'b', template: `<p>{{ x }}</p>` })\nexport class B {}\n")
    assert [(m["class"], m["templateUrl"], m["template"]) for m in meta] == [
        ("A", "./a.html", None), ("B", None, "<p>{{ x }}</p>")]


# --- templates ------------------------------------------------------------------------

def test_interpolation_and_loop_variables_are_text():
    tpl = '<div *ngFor="let m of errorMsg">{{ m }}</div>\n<p>{{ other }}</p>'
    consumers = ar.template_consumers(tpl, "t.html", {"errorMsg"})
    assert [(c.context, c.where) for c in consumers] == [(ar.TEXT, "t.html:1")]


def test_the_new_control_flow_loop_behaves_the_same():
    tpl = "@for (m of errorMsg; track m) {\n  <li>{{ m }}</li>\n}"
    consumers = ar.template_consumers(tpl, "t.html", {"errorMsg"})
    assert [(c.context, c.where) for c in consumers] == [(ar.TEXT, "t.html:2")]


def test_async_alias_and_binding_kinds():
    tpl = ('<ng-container *ngIf="(msg$ | async) as m">\n<span [title]="m"></span>\n<div [innerHTML]="m"></div>\n</ng-container>')
    got = {(c.context) for c in ar.template_consumers(tpl, "t.html", {"msg$"})}
    assert got == {ar.TEXT, ar.ANGULAR_HTML}


def test_a_child_component_input_and_a_custom_pipe_on_inner_html_are_unknown():
    tpl = '<app-child [msg]="msg"></app-child>\n<div [innerHTML]="msg | fancy"></div>'
    got = [c.context for c in ar.template_consumers(tpl, "t.html", {"msg"})]
    assert got == [ar.UNKNOWN, ar.UNKNOWN]


# --- decisions --------------------------------------------------------------------------

def test_translation_pushed_to_a_loop_rendered_as_text_is_a_proof(tmp_path):
    _write(tmp_path, "src/app/err.component.ts", _component("err", "templateUrl: './err.component.html'", """
  errorMsg: string[] = [];
  load(key: string) {
    this.translate.get(key).subscribe((res: string) => {
      this.errorMsg.push(res);
    });
  }
"""))
    _write(tmp_path, "src/app/err.component.html", '<div *ngFor="let m of errorMsg">{{ m }}</div>\n')
    f, mine = _decide(tmp_path, "src/app/err.component.ts", "this.errorMsg.push(res)")
    assert mine == [("negative_proof", "angular_text_interpolation")]
    assert f["verdict"] == "false_positive"
    assert "err.component.html:1" in f["verdict_reason"]


def test_a_translation_bound_to_inner_html_through_a_bypass_stays_found(tmp_path):
    _write(tmp_path, "src/app/rich.component.ts", _component("rich", "templateUrl: './rich.component.html'", """
  html = '';
  safeHtml: any;
  constructor2(private sanitizer: any) {}
  show(key: string) {
    this.html = this.translate.instant(key);
    this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(this.html);
  }
"""))
    _write(tmp_path, "src/app/rich.component.html", '<div [innerHTML]="safeHtml"></div>\n<p>{{ html }}</p>\n')
    f, mine = _decide(tmp_path, "src/app/rich.component.ts", "this.html = this.translate.instant")
    assert mine == [("positive_fact", "angular_unsafe_render")]
    assert f["verdict"] == "true_positive"
    f, mine = _decide(tmp_path, "src/app/rich.component.ts", "this.html = this.translate.instant", verdict="false_positive")
    assert f["verdict"] == "unverified" and f["unresolved_reason"] == "conflict"


def test_a_value_also_written_with_native_element_inner_html_is_positive(tmp_path):
    _write(tmp_path, "src/app/nat.component.ts", _component("nat", "template: '<p>{{ text }}</p>'", """
  text = '';
  el: any;
  show(key: string) {
    this.text = this.translate.instant(key);
    this.el.nativeElement.innerHTML = this.text;
  }
"""))
    f, mine = _decide(tmp_path, "src/app/nat.component.ts", "this.text = this.translate.instant")
    assert mine == [("positive_fact", "angular_unsafe_render")]


def test_the_rules_that_are_the_dangerous_contexts_are_never_touched(tmp_path):
    _write(tmp_path, "src/app/nat.component.ts", _component("nat", "template: '<p>{{ text }}</p>'", """
  text = '';
  el: any;
  show() {
    this.el.nativeElement.innerHTML = this.text;
  }
"""))
    f, mine = _decide(tmp_path, "src/app/nat.component.ts", "innerHTML", rule_id="innerhtml-assign")
    assert mine == [] and f["verdict"] == "true_positive"


def test_sanitised_inner_html_is_noted_but_script_cannot_run(tmp_path):
    _write(tmp_path, "src/app/s.component.ts", _component("s", "template: '<div [innerHTML]=\"msg\"></div><p>{{ msg }}</p>'", """
  msg = '';
  show() {
    this.msg = this.translate.instant('K');
  }
"""))
    f, mine = _decide(tmp_path, "src/app/s.component.ts", "this.msg = ")
    assert mine == [("negative_proof", "angular_sanitised_html")]


def test_a_missing_template_a_child_component_or_no_consumer_is_a_named_gap(tmp_path):
    _write(tmp_path, "src/app/g.component.ts", _component("g", "templateUrl: './missing.html'", """
  msg = '';
  show() {
    this.msg = this.translate.instant('K');
  }
"""))
    f, mine = _decide(tmp_path, "src/app/g.component.ts", "this.msg = ")
    assert mine == [("evidence_gap", None)]
    assert "missing.html" in f["verdict_reason"]

    _write(tmp_path, "src/app/c.component.ts", _component("c", "template: '<app-child [msg]=\"msg\"></app-child>'", """
  msg = '';
  show() {
    this.msg = this.translate.instant('K');
  }
"""))
    f, mine = _decide(tmp_path, "src/app/c.component.ts", "this.msg = ")
    assert mine == [("evidence_gap", None)]

    _write(tmp_path, "src/app/n.component.ts", _component("n", "template: '<p>nothing</p>'", """
  msg = '';
  show() {
    this.msg = this.translate.instant('K');
  }
"""))
    f, mine = _decide(tmp_path, "src/app/n.component.ts", "this.msg = ")
    assert mine == [("evidence_gap", None)]


def test_a_custom_translate_compiler_in_the_app_is_a_gap(tmp_path):
    _write(tmp_path, "src/app/t.component.ts", _component("t", "template: '<p>{{ msg }}</p>'", """
  msg = '';
  show() {
    this.msg = this.translate.instant('K');
  }
"""))
    _write(tmp_path, "src/app/my-compiler.ts",
           "import { TranslateCompiler } from '@ngx-translate/core';\n"
           "export class MyCompiler implements TranslateCompiler {\n  compile(v: string) { return v; }\n}\n")
    f, mine = _decide(tmp_path, "src/app/t.component.ts", "this.msg = ")
    assert mine == [("evidence_gap", None)]
    assert "my-compiler.ts" in f["verdict_reason"]


def test_code_execution_needs_an_evaluator_not_a_dictionary_lookup(tmp_path):
    _write(tmp_path, "src/app/e.component.ts", _component("e", "template: '<p>{{ msg }}</p>'", """
  msg = '';
  show() {
    this.msg = this.translate.instant('K');
  }
"""))
    f, mine = _decide(tmp_path, "src/app/e.component.ts", "this.msg = ", cwe="CWE-94")
    assert mine == [("negative_proof", "angular_no_evaluator")]

    _write(tmp_path, "src/app/ev.component.ts", _component("ev", "template: '<p>{{ msg }}</p>'", """
  msg = '';
  show() {
    this.msg = this.translate.instant('K');
    const code = this.msg;
    eval(code);
  }
"""))
    f, mine = _decide(tmp_path, "src/app/ev.component.ts", "this.msg = ", cwe="CWE-94")
    assert mine == [("positive_fact", "angular_unsafe_render")]


def test_a_cwe_532_finding_on_the_same_line_is_untouched(tmp_path):
    _write(tmp_path, "src/app/e.component.ts", _component("e", "template: '<p>{{ msg }}</p>'", """
  msg = '';
  show() {
    this.msg = this.translate.instant('K');
  }
"""))
    f, mine = _decide(tmp_path, "src/app/e.component.ts", "this.msg = ", cwe="CWE-532")
    assert mine == [] and f["verdict"] == "true_positive"
