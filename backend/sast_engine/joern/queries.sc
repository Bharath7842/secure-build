// queries.sc — structural CPG queries for pipeline/joern_findings.py.
//
// Run via joern_runner.run_script:
//   joern --script queries.sc --param cpgFile=... --param outFile=...
//
// Deliberately limited to checks the regex catalog can't express well:
// absence-within-a-method (XML parser built with no hardening call), method
// bodies that are empty/return a constant (trust-all TLS), and argument shape
// (non-literal format string). Source->sink taint lives in flows.sc instead.
//
// Writes {"hits": [{query, title, cwe, score, description, file, line, code}]}
// to outFile. Hits are unverified — joern_findings.py routes them through the
// same grouped LLM confirmation as regex hits.

import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*

@main def exec(cpgFile: String, outFile: String, maxHits: Int = 2000) = {
  importCpg(cpgFile)

  val hits = ujson.Arr()

  def hit(query: String, title: String, cwe: String, score: Double, description: String, n: AstNode, file: String): Unit = {
    if (hits.value.size < maxHits) {
      hits.value += ujson.Obj(
        "query" -> query,
        "title" -> title,
        "cwe" -> cwe,
        "score" -> score,
        "description" -> description,
        "file" -> file,
        "line" -> n.lineNumber.map(_.intValue()).getOrElse(-1),
        "code" -> n.code.take(300)
      )
    }
  }

  def callHit(query: String, title: String, cwe: String, score: Double, description: String, c: Call): Unit =
    hit(query, title, cwe, score, description, c, c.method.filename)

  def methodHit(query: String, title: String, cwe: String, score: Double, description: String, m: Method): Unit =
    hit(query, title, cwe, score, description, m, m.filename)

  def isLiteral(e: Expression): Boolean = e.isInstanceOf[Literal]

  // --- C/C++: memory-unsafe libc calls --------------------------------------
  cpg.call.name("gets|strcpy|strcat|sprintf|vsprintf|stpcpy|wcscpy|wcscat").filter(_.method.filename.matches(".*\\.(c|cc|cpp|cxx|h|hpp)$")).foreach { c =>
    callHit("c-unbounded-copy", "Unbounded buffer copy via " + c.name, "CWE-120", 7.0,
      "Call to a libc function with no destination-size bound; overflow if the source is longer than the buffer.", c)
  }

  // --- C/C++: non-literal format string -------------------------------------
  val fmtPos = Map("printf" -> 1, "vprintf" -> 1, "syslog" -> 2, "fprintf" -> 2, "sprintf" -> 2, "vfprintf" -> 2, "snprintf" -> 3, "vsnprintf" -> 3)
  cpg.call.name(fmtPos.keys.mkString("|")).filter(_.method.filename.matches(".*\\.(c|cc|cpp|cxx|h|hpp)$")).foreach { c =>
    c.argument.argumentIndex(fmtPos(c.name)).headOption.foreach { a =>
      if (!isLiteral(a)) callHit("c-format-string", "Non-literal format string passed to " + c.name, "CWE-134", 8.0,
        "The format argument is not a string literal; attacker-controlled format specifiers can read or write memory.", c)
    }
  }

  // --- Java: XML parser factories with no hardening in the same method ------
  val xmlFactories = "javax\\.xml\\.(parsers\\.(DocumentBuilderFactory|SAXParserFactory)|stream\\.XMLInputFactory|transform\\.TransformerFactory)\\.newInstance.*|org\\.xml\\.sax\\.helpers\\.XMLReaderFactory\\..*"
  cpg.call.methodFullName(xmlFactories).foreach { c =>
    val hardened = c.method.call.name("setFeature|setProperty|setAttribute|setXIncludeAware|setExpandEntityReferences").nonEmpty
    if (!hardened) callHit("java-xxe-unhardened-parser", "XML parser factory created without XXE hardening", "CWE-611", 7.0,
      "The factory is created and used in this method with no setFeature/setProperty call disabling DTDs or external entities.", c)
  }

  // --- Java: trust-all TLS ---------------------------------------------------
  cpg.method.name("checkServerTrusted|checkClientTrusted").filter(_.filename.endsWith(".java")).foreach { m =>
    val throws = m.ast.isCall.name("<operator>.throw").nonEmpty || m.ast.isCall.name("<operator>.throw|throw").nonEmpty || m.ast.code("throw .*").nonEmpty
    val callsOut = m.call.filterNot(_.name.startsWith("<operator>")).nonEmpty
    if (!throws && !callsOut) methodHit("java-trust-all-certificates", "X509TrustManager accepts every certificate", "CWE-295", 8.0,
      "The trust-manager check neither validates the chain nor throws, so any certificate (including a MITM one) is accepted.", m)
  }
  cpg.method.name("verify").filter(_.filename.endsWith(".java")).filter(_.parameter.size == 3).foreach { m =>
    val returnsTrue = m.ast.isReturn.code("return true;?").nonEmpty
    val onlyTrue = m.ast.isReturn.l.forall(_.code.matches("return true;?"))
    if (returnsTrue && onlyTrue) methodHit("java-hostname-verifier-accepts-all", "HostnameVerifier accepts every host", "CWE-297", 7.0,
      "verify() always returns true, disabling hostname verification for TLS connections.", m)
  }

  // --- Java: weak hashing / ciphers (literal algorithm names) ---------------
  cpg.call.methodFullName("java\\.security\\.MessageDigest\\.getInstance.*").foreach { c =>
    c.argument.argumentIndex(1).isLiteral.code("\"(MD2|MD4|MD5|SHA-?1|SHA)\"").headOption.foreach { _ =>
      callHit("java-weak-hash", "Weak hash algorithm " + c.argument.argumentIndex(1).code.headOption.getOrElse(""), "CWE-328", 5.0,
        "MD5/SHA-1 are collision-broken and unsuitable for passwords, signatures or integrity checks.", c)
    }
  }
  cpg.call.methodFullName("javax\\.crypto\\.Cipher\\.getInstance.*").foreach { c =>
    c.argument.argumentIndex(1).isLiteral.code("\"(?i)(DES|DESede|3DES|RC2|RC4|Blowfish|AES)(/ECB.*)?\"|\"(?i)[^\"]*/ECB/[^\"]*\"").headOption.foreach { a =>
      callHit("java-weak-cipher", "Weak cipher or ECB mode " + a.code, "CWE-327", 6.0,
        "Broken cipher, or a block cipher in ECB mode (bare \"AES\" defaults to ECB), which leaks plaintext patterns.", c)
    }
  }

  // --- Java: cookie created without Secure/HttpOnly in the same method ------
  cpg.call.methodFullName("(jakarta|javax)\\.servlet\\.http\\.Cookie\\.<init>.*").foreach { c =>
    val m = c.method
    val secure = m.call.name("setSecure").nonEmpty
    val httpOnly = m.call.name("setHttpOnly").nonEmpty
    if (!secure || !httpOnly) callHit("java-cookie-missing-flags",
      "Cookie created without " + List(if (!secure) Some("Secure") else None, if (!httpOnly) Some("HttpOnly") else None).flatten.mkString(" or "),
      if (!httpOnly) "CWE-1004" else "CWE-614", 4.0,
      "The servlet cookie is built in this method with no setSecure(true)/setHttpOnly(true) call.", c)
  }

  // --- Python: shell=True / debug=True --------------------------------------
  def kwTrue(c: Call, name: String): Boolean =
    c.argument.exists(a => (a.argumentName.contains(name) && a.code == "True") || a.code.matches(name + "\\s*=\\s*True"))
  cpg.call.filter(_.method.filename.endsWith(".py")).filter(c => kwTrue(c, "shell")).foreach { c =>
    callHit("python-subprocess-shell-true", "Subprocess invoked with shell=True", "CWE-78", 6.0,
      "shell=True runs the command through /bin/sh; any interpolated value becomes command injection.", c)
  }
  cpg.call.name("run").filter(_.method.filename.endsWith(".py")).filter(c => kwTrue(c, "debug")).foreach { c =>
    callHit("python-debug-mode-enabled", "Web app started with debug=True", "CWE-489", 5.0,
      "Flask/Werkzeug debug mode exposes an interactive debugger that allows code execution.", c)
  }

  // --- All languages: hardcoded credential assigned to a named variable -----
  cpg.assignment.foreach { a =>
    val lhs = a.target.code
    a.source match {
      case lit: Literal if lhs.matches("(?i).*\\b[\\w.]*(password|passwd|pwd|secret|api_?key|access_?key|private_?key|auth_?token)\\b.*") &&
          lit.code.matches("[\"'][^\"'$%{}<>]{6,}[\"']") &&
          !lit.code.matches("(?i)[\"'](changeme|change_me|password|secret|xxx+|\\*+|your[_-].*|<.*>|todo|test.*|example.*|dummy.*)[\"']") =>
        hit("hardcoded-credential", "Hardcoded credential assigned to " + lhs.take(80), "CWE-798", 6.0,
          "A non-placeholder string literal is assigned to a credential-named variable.", a, a.method.filename)
      case _ =>
    }
  }

  os.write.over(os.Path(outFile), ujson.write(ujson.Obj("hits" -> hits)))
}
