// flows.sc — interprocedural source->sink dataflows for pipeline/joern_flows.py.
//
// Run via joern_runner.run_script:
//   joern --script flows.sc --param cpgFile=... --param specFile=... \
//         --param outFile=... --param maxFlows=200
//
// Writes a JSON object to outFile; never prints results to stdout (Joern's
// banner/log output there is not a stable format). Each flows[] element:
//   {"sink_kind": str, "sink_code": str,
//    "elements": [{file, line, method, method_full_name, method_line, method_line_end, code}],
//    "guards": [{file, line, code}],       // CDG: conditions the path's nodes depend on
//    "sanitizers": [{file, line, code}],   // spec sanitizer calls the value passes through
//    "source_annotations": [str]}          // annotations on the source method + its type
// The Python side collapses elements into per-method hops and re-reads method
// bodies from disk. Guards and sanitizers only annotate a flow — nothing here
// drops a path because of them; the LLM verifier makes that call.
//
// Sink kinds run one at a time in the spec's kind_order, and outFile is
// rewritten after each with "complete": false, so a timeout on a late,
// low-priority kind (log, response_body) still leaves the earlier kinds'
// flows for joern_runner to read back.

import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.codepropertygraph.generated.nodes.*

@main def exec(cpgFile: String, specFile: String, outFile: String, maxFlows: Int = 200) = {
  importCpg(cpgFile)
  given EngineContext = EngineContext()

  val spec = ujson.read(os.read(os.Path(specFile)))
  val src = spec("sources")

  def opt(v: ujson.Value, key: String): Option[String] =
    v.obj.get(key).map(_.str).filter(_.nonEmpty)

  def matchesCall(c: Call, v: ujson.Value): Boolean = {
    val nameOk = opt(v, "name").forall(re => c.name.matches(re))
    val fullOk = opt(v, "full_name").forall(re => c.methodFullName.matches(re))
    val codeOk = opt(v, "code").forall(re => c.code.matches("(?s)" + re))
    nameOk && fullOk && codeOk
  }

  // --- sources ---------------------------------------------------------------
  val entryAnn = src("entry_annotations").str
  val paramAnn = src("param_annotations").str
  // Framework-injected entry-method parameters that carry no request input
  // (the response object, the view model, the principal, ...).
  val nonSourceTypes = opt(src, "non_source_param_types").getOrElse("$^")

  val annotatedParams: List[CfgNode] =
    cpg.method.where(_.annotation.name(entryAnn)).parameter
      .filterNot(_.name == "this")
      .filterNot(_.typeFullName.matches(nonSourceTypes)).l ++
    cpg.parameter.where(_.annotation.name(paramAnn)).l

  val allCalls = cpg.call.l
  val accessorSpecs = src("accessor_calls").arr.toList
  val accessorCalls: List[CfgNode] =
    allCalls.filter(c => accessorSpecs.exists(s => matchesCall(c, s)))

  val codePatterns = src("code_patterns").arr.toList.map(_.str)
  val codeSources: List[CfgNode] =
    allCalls.filter(c =>
      c.name.startsWith("<operator>.fieldAccess") || c.name.startsWith("<operator>.indexAccess") || !c.name.startsWith("<operator>")
    ).filter(c => codePatterns.exists(p => c.code.matches("(?s)" + p)))

  val sources = (annotatedParams ++ accessorCalls ++ codeSources).distinct

  // --- sinks -----------------------------------------------------------------
  val sinkSpecs = spec("sinks").arr.toList
  val sinkKinds: Map[Long, String] = allCalls.flatMap { c =>
    sinkSpecs.find(s => matchesCall(c, s)).map(s => c.id() -> s("kind").str)
  }.toMap
  val kindOrder = spec.obj.get("kind_order").map(_.arr.map(_.str).toList).getOrElse(Nil)
  val kinds = sinkKinds.values.toList.distinct.sortBy { k =>
    val i = kindOrder.indexOf(k)
    if (i < 0) Int.MaxValue else i
  }

  // --- sanitizers ------------------------------------------------------------
  // A spec without "kinds" sanitizes every sink kind.
  val sanitizerSpecs = spec.obj.get("sanitizers").map(_.arr.toList).getOrElse(Nil)
  def sanitizes(c: Call, kind: String): Boolean =
    sanitizerSpecs.exists(s => matchesCall(c, s) && s.obj.get("kinds").forall(_.arr.exists(_.str == kind)))

  // Calls a path element is, or is an argument of.
  def callsAt(n: CfgNode): List[Call] = n match {
    case c: Call => List(c)
    case e: Expression => e.inCall.l
    case _ => Nil
  }

  def lineOf(n: CfgNode): Int = n.lineNumber.map(_.intValue()).getOrElse(-1)

  def locJson(n: CfgNode): ujson.Obj = ujson.Obj(
    "file" -> n.method.filename,
    "line" -> lineOf(n),
    "code" -> n.code.take(200)
  )

  def elementJson(n: CfgNode): ujson.Obj = {
    val m = n.method
    ujson.Obj(
      "file" -> m.filename,
      "line" -> lineOf(n),
      "method" -> m.name,
      "method_full_name" -> m.fullName,
      "method_line" -> m.lineNumber.map(_.intValue()).getOrElse(-1),
      "method_line_end" -> m.lineNumberEnd.map(_.intValue()).getOrElse(-1),
      "code" -> n.code.take(300)
    )
  }

  val maxGuards = 8
  val maxSanitizers = 5

  val out = ujson.Arr()
  val done = ujson.Arr()
  def flush(complete: Boolean): Unit =
    os.write.over(os.Path(outFile), ujson.write(ujson.Obj(
      "sources" -> sources.size,
      "sinks" -> sinkKinds.size,
      "kinds_done" -> done,
      "complete" -> complete,
      "flows" -> out
    )))

  val seen = scala.collection.mutable.Set[(String, String)]()
  kinds.foreach { kind =>
    val ids = sinkKinds.collect { case (id, k) if k == kind => id }.toSeq
    val sinkArgs = cpg.call.id(ids*).argument.l
    var kept = 0
    if (sources.nonEmpty && sinkArgs.nonEmpty) {
      sinkArgs.reachableByFlows(sources).l.foreach { p =>
        val elems: List[CfgNode] = p.elements.collect { case c: CfgNode => c }
        if (elems.nonEmpty && kept < maxFlows) {
          val last = elems.last
          val sinkCall: Option[Call] = last match {
            case c: Call if sinkKinds.get(c.id()).contains(kind) => Some(c)
            case e: Expression => e.inCall.find(c => sinkKinds.get(c.id()).contains(kind))
            case _ => None
          }
          sinkCall.foreach { sc =>
            // By source node, not source line: two parameters declared on one
            // line are different sources.
            val key = (elems.head.id().toString, sc.id().toString)
            if (!seen.contains(key)) {
              seen += key
              kept += 1
              val guards = (elems :+ sc).flatMap(_.controlledBy.l)
                .distinctBy(_.id()).sortBy(lineOf).take(maxGuards)
              val sanitizers = elems.flatMap(callsAt).distinctBy(_.id())
                .filter(c => c.id() != sc.id() && sanitizes(c, kind)).take(maxSanitizers)
              val headMethod = elems.head.method
              val annotations = (headMethod.annotation.name.l ++
                headMethod.definingTypeDecl.annotation.name.l).distinct
              out.value += ujson.Obj(
                "sink_kind" -> kind,
                "sink_code" -> sc.code.take(300),
                "elements" -> ujson.Arr.from(elems.map(elementJson)),
                "guards" -> ujson.Arr.from(guards.map(locJson)),
                "sanitizers" -> ujson.Arr.from(sanitizers.map(locJson)),
                "source_annotations" -> ujson.Arr.from(annotations.map(ujson.Str(_)))
              )
            }
          }
        }
      }
    }
    done.value += kind
    flush(complete = false)
  }
  flush(complete = true)
}
