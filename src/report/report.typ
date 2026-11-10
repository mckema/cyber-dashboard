// Cyber threat report. Compiled by report/pdf.rs with data.json (report.json
// plus data_sha) next to it; only typst's embedded fonts are used. One template for
// the monthly report and the month-to-date snapshot: page 1 the
// summary for management, page 2 the month in review, then the audit appendix.
// Each fact appears once.
#let d = json("data.json")
// Data marking ("" in production): "LAB DATA" (EW_ENVIRONMENT=lab) or "TEST DATA".
#let mark = d.marking.label
#let marked = mark != ""
#let mtd = d.period.kind == "month-to-date"

// FIRST TLP 2.0: the label (REPORT_TLP, d.document.tlp) in its colour on black, at least
// 11 pt: RED #FF2B2B, AMBER and AMBER+STRICT #FFC000, GREEN #33FF00, CLEAR white.
#let tlp-label = d.document.tlp
#let tlp-colours = (("TLP:RED", rgb("#FF2B2B")), ("TLP:GREEN", rgb("#33FF00")), ("TLP:CLEAR", white))
#let tlp-colour = tlp-colours.fold(rgb("#FFC000"), (c, p) => if tlp-label.starts-with(p.at(0)) { p.at(1) } else { c })
#let tlp = box(fill: black, inset: (x: 5pt, y: 3pt), radius: 1pt,
  text(fill: tlp-colour, weight: "bold", font: "DejaVu Sans Mono", size: 11pt)[#tlp-label])
// REPORT_ORG ("" = not named): PDF author, page header and document control.
#let org = d.document.organisation
#let marktag = box(fill: rgb("#B00020"), inset: (x: 4pt, y: 3pt), radius: 1pt,
  text(fill: white, weight: "bold", font: "DejaVu Sans Mono", size: 9pt)[#mark])

#let rag-fill = (GREEN: rgb("#1e7b34"), AMBER: rgb("#c77700"), RED: rgb("#b00020"))
#let rag-tint = (Green: rgb("#e3f2e6"), Amber: rgb("#fff1d6"), Red: rgb("#fbe3e6"))
#let red = rgb("#b00020")
#let muted(body) = text(size: 7.5pt, fill: luma(70), body)

// Times in data.json are Amsterdam local with offset: "YYYY-MM-DD HH:MM", or the date.
#let short(t) = if t == none { "–" } else { t.slice(0, 16).replace("T", " ") }
#let day(t) = if t == none { "–" } else { t.slice(0, 10) }
#let dash(s) = if s == none or s == "" { "—" } else { str(s) }
#let num(x) = if x == none { "—" } else { str(x) }
// 3855 -> "3,855"
#let thou(n) = {
  let s = str(n)
  let c = s.clusters()
  let out = ""
  for (i, ch) in c.enumerate() {
    if i > 0 and calc.rem(c.len() - i, 3) == 0 { out += "," }
    out += ch
  }
  out
}
#let cut(s, n) = {
  let c = s.clusters()
  if c.len() > n { c.slice(0, n).join() + "…" } else { s }
}
// A GitHub advisory id (GHSA-xxxx-xxxx-xxxx) links to its record, as the CC BY 4.0
// attribution of the GitHub Advisory Database (see "Sources and licences").
#let ghsa(s, body) = {
  let m = s.match(regex("GHSA(-[0-9a-z]{4}){3}"))
  if m == none { body } else { link("https://github.com/advisories/" + m.text, body) }
}
#let ticket(i) = if i.identifier == "" { ghsa(i.key, text(size: 7.5pt, i.key)) } else if i.url == "" { i.identifier } else { link(i.url, i.identifier) }
#let vuln(i, n) = [#ghsa(i.vulnerability, i.vulnerability) \ #muted(cut(i.title, n))]
#let carried(i) = if i.at("carried_over", default: false) [ †]

#set document(title: d.title, author: if org == "" { "Cyber Threat Dashboard" } else { "Cyber Threat Dashboard (" + org + ")" })
#set text(font: "Libertinus Serif", size: 10pt, lang: "en")
#set par(justify: false, leading: 0.55em)
#set page(
  paper: "a4",
  margin: (x: 1.6cm, top: 2.1cm, bottom: 1.9cm),
  header: {
    set text(size: 8.5pt)
    grid(columns: (1fr, auto), align: (left + horizon, right + horizon), column-gutter: 6pt,
      [#if org != "" [#org · ]Cyber threat report · #d.period.month · #d.document.id],
      { if marked { marktag; h(4pt) }; tlp })
    v(-3pt)
    line(length: 100%, stroke: 0.4pt + gray)
  },
  footer: context {
    set text(size: 8pt, fill: luma(70))
    grid(columns: (auto, 1fr), column-gutter: 6pt, align: (left + horizon, left + horizon),
      tlp, [· Page #counter(page).display() / #counter(page).final().first()])
  },
  background: if marked {
    rotate(-35deg, text(size: 96pt, weight: "bold", fill: rgb(176, 0, 32, 22))[#mark])
  },
)
#set table(stroke: 0.4pt + luma(170), inset: (x: 4pt, y: 3pt))
#show table: set text(size: 8.5pt)
#show heading.where(level: 1): set text(size: 13pt)
#show heading.where(level: 1): set block(above: 0.9em, below: 0.6em)
#show heading.where(level: 2): set text(size: 11pt)
#show heading.where(level: 2): set block(above: 1.0em, below: 0.45em)
#show link: set text(fill: rgb("#1a4f8b"))

#let none-row = emph[None.]
#let notice(fill, stroke, body) = block(fill: fill, stroke: 0.6pt + stroke, inset: (x: 6pt, y: 4pt), width: 100%, below: 0.5em, text(size: 9pt, body))
#let doc-status = if mtd [Snapshot – not the monthly report] else [#d.document.status]
#let so-far(month, now) = if mtd { now } else { month }

// ================================================================== page 1: summary
#text(size: 16pt, weight: "bold")[#d.title] \
#text(size: 9pt, fill: luma(50))[*#doc-status* · #d.document.id · Period #d.period.text · tickets as of #short(d.tickets_as_of)]

// The data marking is the header tag and the watermark only (no notice box on
// page 1); `marking.notice` stays in report.json.
#if d.coverage.partial {
  notice(rgb("#fff4d6"), rgb("#c58a00"))[*Partial history* – the event log starts after the beginning of the period (see the appendix); figures before it are incomplete.]
}

// ------------------------------------------------------------------ status and bottom line
#let rag = d.status.rag
#block(stroke: 0.8pt + rag-fill.at(rag), inset: 7pt, width: 100%, radius: 2pt, above: 0.8em, below: 0.6em)[
  #grid(columns: (auto, 1fr), column-gutter: 10pt, align: (center + horizon, left + horizon),
    box(fill: rag-fill.at(rag), inset: (x: 8pt, y: 6pt), radius: 2pt)[
      #set align(center)
      #text(fill: white, size: 7.5pt)[OVERALL STATUS] \
      #text(fill: white, size: 15pt, weight: "bold")[#rag]
    ],
    d.bottom_line.join(" "),
  )
]

// ------------------------------------------------------------------ key figures
== Key figures
#let status-cell(s) = if s == "—" { [—] } else {
  table.cell(fill: rag-tint.at(s))[#text(fill: rag-fill.at(upper(s)), weight: "bold")[#s]]
}
// A target that is not agreed yet carries a footnote mark; the note is under the table.
#let noted = d.kpis.filter(k => k.target_note != none)
#let target-cell(k) = if k.target_note == none { k.target } else [#k.target#super[\*]]
#let trend-cell(t) = if t in ("▲", "▼", "=") { text(font: "DejaVu Sans Mono", size: 9pt, t) } else { muted(t) }
#table(columns: (1fr, auto, auto, auto, auto, auto),
  align: (left, left, left, left, left, center),
  table.header([*Measure*], [*#so-far([This month], [So far])*], [*Target*], [*Status*], [*Previous month#if d.previous.covered and d.previous.partial [ (partial)]*], [*Trend*]),
  ..d.kpis.map(k => (k.label, k.value, target-cell(k), status-cell(k.status), k.previous, trend-cell(k.at("trend", default: "—")))).flatten())
#if noted.len() > 0 [
  #v(-4pt)
  #muted[\* Target: #noted.map(k => k.target_note).dedup().join("; ").]
]

// ------------------------------------------------------------------ attention
== Decisions and attention
#if d.attention.len() == 0 [
  #if mtd [None so far.] else [None.]
] else {
  set text(size: 9.5pt)
  list(..d.attention.map(a => [#text(fill: rag-fill.at(a.rag), weight: "bold", size: 8pt)[#a.rag] #a.text]))
}

// ================================================================== page 2: the month in review
#pagebreak()
= #if mtd [The month so far] else [The month in review]

#let f = d.funnel
#let by = f.by_source.map(s => [#s.source #s.relevant of #thou(s.total)]).join(", ")
#let slow = f.over_one_day.filter(i => i.assessed_at != none)
// Intake as a funnel diagram; its counts are not repeated in text.
== Intake and assessment
#let stage(n, l) = box(stroke: 0.4pt + luma(150), inset: (x: 5pt, y: 4pt), radius: 2pt)[
  #align(center)[#text(size: 13pt, weight: "bold", if type(n) == content { n } else { thou(n) }) \ #text(size: 7.5pt, l)]]
#let arrow = text(size: 12pt, fill: luma(110))[→]
#grid(columns: (1fr, auto, 1fr, auto, 1fr, auto, 1fr, auto, 1.3fr), column-gutter: 3pt, align: horizon,
  stage(f.notices, [new public notices]), arrow,
  stage(f.auto_ruled_out, [automatically ruled out]), arrow,
  stage(f.relevant, [relevant]), arrow,
  stage(f.assessed, [assessed]), arrow,
  stage([#f.action_planned / #f.ruled_out_by_person / #f.waiting], [action planned / ruled out by a person / waiting]),
)
#if f.by_source.len() > 0 [#text(size: 8pt)[Relevant of notices, by source: #by.]]

#if f.time_to_assess.count > 0 [*Time to assess* (business hours): median #num(f.time_to_assess.median_business_hours) h, maximum #num(f.time_to_assess.max_business_hours) h#if slow.len() > 0 [; assessed after more than 1 business day: #slow.map(i => [#i.identifier (#num(i.business_hours) h)]).join(", ")].]

// ------------------------------------------------------------------ action backlog
#let b = d.backlog
#let term(sign, n, l) = if n != 0 [ #sign #n #l]
*Action backlog.* Open at the start of the month #b.open_start#term("+", b.accepted, [accepted])#term("+", b.reopened, [reopened])#term("−", b.fixed, [fixed])#term("−", b.closed_without_fix, [closed without fix])#if b.other > 0 [ \+ #b.other other] else if b.other < 0 [ − #calc.abs(b.other) other (for example moved back to triage)] = *#b.open_end #if mtd [open now] else [open at the end of the month]*.

// ------------------------------------------------------------------ open actions
#let oa = d.open_actions.items
== Open actions #if mtd [now] else [at month end] (#oa.len())
#if oa.len() == 0 [
  None: no action is open.
] else {
  table(columns: (auto, 1fr, auto, auto, auto, auto, auto, auto),
    align: (left, left, left, left, left, left, left, right),
    table.header([*Ticket*], [*Vulnerability*], [*Component*], [*Exploited · severity*], [*Owner*], [*Due*], [*Status*], [*Age (d)*]),
    ..oa.map(i => {
      let f = if i.overdue { rgb("#fbe3e6") } else { none }
      let sev = if i.severity == "" { "—" } else if i.score == none { i.severity } else [#i.severity #i.score]
      (
        table.cell(fill: f)[#ticket(i)#carried(i)],
        table.cell(fill: f, vuln(i, 55)),
        table.cell(fill: f, dash(i.component)),
        table.cell(fill: f)[#if i.exploited [*yes* #muted(i.exploited_source)] else [no] · #sev],
        table.cell(fill: f, if i.owner == "" { text(fill: red, weight: "bold")[none] } else { i.owner }),
        table.cell(fill: f, if i.due == "" { text(fill: red, weight: "bold")[none] } else if i.overdue [*#i.due* \ #text(size: 7pt, fill: red, weight: "bold")[OVERDUE]] else { i.due }),
        table.cell(fill: f, dash(i.state_name)),
        table.cell(fill: f, num(i.at("age_days", default: none))),
      )
    }).flatten())
  if oa.any(i => i.at("carried_over", default: false)) { muted[† first seen in an earlier month. Age: calendar days since first seen.] } else { muted[Age: calendar days since first seen.] }
}

// ------------------------------------------------------------------ closed
#let rs = d.resolved
#let outcome = (fixed: [Fixed], closed_without_fix: [Closed without fix], ruled_out: [Ruled out])
// "Resolved", not "Closed": the dashboard's "Closed this month" counts actions only
// (fixed + closed without fix); this table also lists items ruled out by a person.
#let n-of = k => rs.filter(r => r.kind == k).len()
== Resolved #if mtd [so far] else [in the month] (#rs.len())
#if rs.len() == 0 [
  Nothing was resolved.
] else [
  Actions closed: #n-of("fixed") fixed, #n-of("closed_without_fix") closed without fix · ruled out by a person: #n-of("ruled_out").
]
#if rs.len() > 0 {
  table(columns: (auto, auto, 1fr, auto, 1.3fr, auto),
    table.header([*Outcome*], [*Ticket*], [*Vulnerability*], [*By*], [*Reason or due date*], [*Date*]),
    ..rs.map(r => (
      outcome.at(r.kind),
      ticket(r),
      vuln(r, 45),
      if r.kind == "ruled_out" and r.by == "" { muted[not recorded] } else { dash(r.by) },
      if r.warn { text(fill: red)[#r.detail] } else { dash(r.detail) },
      day(r.date),
    )).flatten())
}

// ------------------------------------------------------------------ waiting
#let w = d.waiting_items
#if w.len() > 0 [
  == Waiting for assessment #if mtd [now] else [at month end] (#w.len())
  #table(columns: (auto, 1fr, auto, auto),
    table.header([*Ticket*], [*Vulnerability*], [*First seen*], [*Flag*]),
    ..w.map(i => (
      [#ticket(i)#carried(i)],
      vuln(i, 60),
      short(i.first_seen),
      {
        let flags = ()
        if i.over_three_days { flags.push(text(fill: red, weight: "bold")[over 3 business days]) } else if i.overdue { flags.push(text(fill: rgb("#c77700"), weight: "bold")[over 1 business day]) }
        if i.declined_without_reason { flags.push([declined without a reason]) }
        if flags.len() == 0 [—] else { flags.join([ · ]) }
      },
    )).flatten())
  #if w.any(i => i.carried_over) { muted[† first seen in an earlier month.] }
]

// ================================================================== appendix
// The appendix starts on its own page, even when the month's
// tables spill over by a few rows.
#pagebreak()
= Appendix (audit)

// Monthly close only (close.rs): the random sample of automatically ruled-out items.
#let sample = d.at("review_sample", default: none)
#if sample != none [
== Quality check sample — automatically ruled-out items
  #set text(size: 9pt)
  A control for the automatic rule-out, which matches by component name only: #sample.items.len() of #thou(sample.candidates) items ruled out automatically in the month, drawn at random before this report was frozen (seed sha256 #raw(sample.seed.slice(0, 16))…, reproducible from the event log). The review reminder in the ticket tracker asks a person to check each one.

  #if sample.items.len() == 0 {
    emph(if sample.note == "" { "No automatically ruled-out items in the period." } else { sample.note })
  } else {
    table(columns: (auto, auto, 1fr, auto),
      table.header([*No.*], [*Item*], [*Title*], [*Vendor / product*]),
      ..sample.items.enumerate().map(((n, i)) => (
        str(n + 1),
        if i.url == "" { ghsa(i.key, text(size: 7.5pt, i.key)) } else { link(i.url, text(size: 7.5pt, i.key)) },
        if i.title == "" { "—" } else { cut(i.title, 90) },
        dash(i.vendor_product),
      )).flatten())
  }
]

== Feed health (last scheduled run)
#if d.feeds.len() == 0 [No scheduled run reported its sources in the period.] else {
  table(columns: (1fr, auto, auto, 2fr, auto),
    table.header([*Source*], [*Runs*], [*OK*], [*Other results*], [*Last run*]),
    ..d.feeds.map(s => (s.feed, str(s.runs), str(s.ok),
      { let o = s.by_status.pairs().filter(((k, v)) => k != "ok"); if o.len() == 0 [—] else { o.map(((k, v)) => k + " " + str(v)).join(", ") } },
      if s.healthy { s.last_status } else { text(fill: red, weight: "bold", s.last_status) })).flatten())
}
#if d.feeds_removed.len() > 0 [
  #muted[Reported earlier in the period, not by the last run: #d.feeds_removed.join(", ").]
]

#let te = d.exceptions.tracker_errors
#if te.len() > 0 [
== Ticket tracker errors (#te.len())
  #table(columns: (auto, 1fr), table.header([*Run*], [*Error*]),
    ..te.map(e => (short(e.run_at), text(size: 8pt, e.error))).flatten())
]

== Definitions
#[
#set text(size: 8.5pt)
#set par(leading: 0.5em)
- *Relevant*: a public vulnerability notice first seen in the period that matches a component on the component list; the others are *automatically ruled out*. Components not on the list and affected versions are not checked.
- *Assessed*: accepted (*action planned*) or declined with a reason (*ruled out by a person*) in the tracker. *Waiting*: still in the triage inbox, or declined without a reason until one is added; it is then assessed at the later of the decline and the reason. Business time: Monday–Friday, Europe/Amsterdam, no holiday calendar.
- *Open action*: accepted and not closed; *overdue*: due date before the end of the period. *Fixed*: done in the tracker, on time when closed on or before the due date. *Closed without fix*: accepted, then canceled.
- *Known exploited*: from CISA KEV or ENISA EUVD, a CVE.org record with CISA SSVC "Exploitation: active", or a CVE seen in CISA KEV or ENISA EUVD by the end of the period.
- *KPIs*: assessed within 1 business day = assessments within 24 business hours ÷ (assessments + items waiting longer), target 100%; fixed by due date = "remediation by due date" (NIST SP 800-40r4, Table 1; NIST sets no target), target ≥ 95%, a team proposal pending agreement; sources healthy = ok or cached in the last scheduled run. *Trend* compares with the previous calendar month when the event log covers it; a month to date shows none.
- *Overall status* (team proposal, 2026-11-05): *RED* = an overdue action on a known-exploited item, an item waiting more than 3 business days, or CISA KEV or CVE.org failing more than 2 days; *AMBER* = an item waiting or assessed after more than 1 business day, an overdue action, an open action without owner or due date, a source stale or failing or no scheduled run, a tracker error, or fixes by due date below 95%; otherwise *GREEN*.
- *Source*: the job's append-only event log and run log, at the times the tracker gives; recording and monitoring of ICT-related threats follow RTS (EU) 2024/1774, Art. 10.
]

// Attribution required by the feeds' terms of use; the same text as the dashboard
// footer (page/skeleton.html, "Sources and licences").
#let cc-by = link("https://creativecommons.org/licenses/by/4.0/")[CC BY 4.0]
#let cc0 = link("https://creativecommons.org/publicdomain/zero/1.0/")[CC0 1.0]
== Sources and licences
#[
#set text(size: 8.5pt)
#set par(leading: 0.5em)
The items in this report come from seven public feeds, used under each publisher's terms. Titles are shortened (cut with "…"); an item is shown by its first CVE or the source's own id, and the source record is authoritative. No publisher endorses this report.
- *CISA Known Exploited Vulnerabilities* (US Cybersecurity & Infrastructure Security Agency), read from the cisagov/kev-data repository: #cc0. Its use implies no endorsement by CISA or DHS.
- *ENISA EU Vulnerability Database*: source: European Union Agency for Cybersecurity (ENISA), #link("https://euvd.enisa.europa.eu/")[EUVD], reproduced with the source acknowledged.
- *CVE List V5* (CVE Program, CVEProject/cvelistV5): used under the #link("https://www.cve.org/Legal/TermsOfUse")[CVE Program Terms of Use]. Copyright © 1999-2026, The MITRE Corporation. CVE is a trademark and the CVE logo is a registered trademark of The MITRE Corporation.
- *NVD CVE API 2.0* (US National Institute of Standards and Technology): This product uses the NVD API but is not endorsed or certified by the NVD. #link("https://nvd.nist.gov/developers/terms-of-use")[NVD terms of use].
- *GitHub Advisory Database*: #link("https://github.com/advisories")[github.com/advisories], licensed #cc-by, and each GHSA id in this report links to its advisory.
- *CERT-EU security advisories*: credit CERT-EU (Cybersecurity Service for the Union institutions, bodies, offices and agencies), licensed #cc-by (#link("https://cert.europa.eu/legal-notice")[legal notice]). Changes: titles shortened.
- *NCSC-NL CSAF advisories* (Nationaal Cyber Security Centrum, Netherlands): #cc0, attribution not required, credited here.
]

== Provenance and document control
#let cov = d.coverage
#let review = if "review_issue" in d { (([Review reminder], [#d.review_issue (Linear)]),) } else { () }
#let rows = (
  ([Document ID], [#d.document.id]),
  ([Version · status], [#d.document.version · #d.document.status]),
  ([Prepared by], [#d.document.prepared_by]),
  ..if org != "" { (([Organisation], [#org]),) } else { () },
  ([Distribution], [#d.document.distribution]),
  ([Retention], [#d.document.retention]),
  ([Period], [#short(d.period.start) to #short(d.period.end) (Europe/Amsterdam; end excluded)#if not d.period.complete [; figures to #short(d.period.data_to)]]),
  ([Generated], [#short(d.generated_at)]),
  ([Tickets as of], [#short(d.tickets_as_of) (last read-back from the tracker included)]),
  ([History covers from], [#short(cov.from)#if cov.partial [ (after the period start: partial)]#[;] #thou(cov.duplicates_dropped) repeated events dropped#if cov.half_written_tail [; a half-written last line skipped]#if d.exceptions.log_lines_skipped > 0 [; #d.exceptions.log_lines_skipped unreadable lines skipped]#if cov.backfilled > 0 [; risk fields of #thou(cov.backfilled) older decisions taken from triage.json]]),
  ([Component list], [#if d.component_list.version == "" [—] else [#d.component_list.version#if d.component_list.count != none [ (#d.component_list.count components)], sha256 #raw(d.component_list.sha256)]#if d.components.len() > 1 [; decisions in the period: #d.components.map(c => [#c.version (#c.decisions)]).join([, ])]]),
  ([Tracker], [#dash(d.tracker.endpoint)]),
  ([Scheduled runs], [#d.runs.writing#if d.runs.writing > 0 [ (#d.runs.by_result.pairs().map(((k, v)) => [#k #v]).join([, ]))]]),
  ([Data sha256], [#raw(d.data_sha) (report.json without its generation time; SHA256SUMS next to the file)]),
  ([Source files], [`triage-events.jsonl` (event log), `runs.jsonl` (run log), `triage.json` (item copies for older decisions); output `report.json`, `report.pdf`, `SHA256SUMS`]),
) + review
#block(breakable: false, table(columns: (auto, 1fr), inset: (x: 5pt, y: 2.5pt),
  ..rows.flatten()))
