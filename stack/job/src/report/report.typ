// Cyber threat report (FR-A4). Compiled by report/pdf.rs with data.json (report.json
// plus data_sha) next to it; only typst's embedded fonts are used. Layout approved
// on 2026-11-05: page 1 for the COO, then detail, then the audit appendix.
#let d = json("data.json")
// Data marking ("" in production): "LAB DATA" (linear-mock) or "TEST DATA", on every page.
#let mark = d.marking.label
#let marked = mark != ""
#let mtd = d.period.kind == "month-to-date"

// FIRST TLP 2.0: the label in amber (#FFC000) on black, at least 11 pt.
#let tlp = box(fill: black, inset: (x: 5pt, y: 3pt), radius: 1pt,
  text(fill: rgb("#FFC000"), weight: "bold", font: "DejaVu Sans Mono", size: 11pt)[TLP:AMBER+STRICT])
#let marktag = box(fill: rgb("#B00020"), inset: (x: 4pt, y: 3pt), radius: 1pt,
  text(fill: white, weight: "bold", font: "DejaVu Sans Mono", size: 9pt)[#mark])

#let rag-fill = (GREEN: rgb("#1e7b34"), AMBER: rgb("#c77700"), RED: rgb("#b00020"))
#let rag-tint = (Green: rgb("#e3f2e6"), Amber: rgb("#fff1d6"), Red: rgb("#fbe3e6"))
#let warn = text(font: "DejaVu Sans Mono", fill: rgb("#c77700"), weight: "bold")[⚠]

// Times in data.json are Amsterdam local with offset: show "YYYY-MM-DD HH:MM".
#let short(t) = if t == none { "–" } else { t.slice(0, 16).replace("T", " ") }
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
#let ticket(i) = if i.identifier == "" { text(size: 7.5pt, i.key) } else { link(i.url, i.identifier) }
#let sev(i) = if i.severity == "" { "—" } else if i.score == none { i.severity } else [#i.severity #text(size: 7.5pt)[#i.score]]

#set document(title: d.title, author: "Exploit Watch (fairCT)")
#set text(font: "Libertinus Serif", size: 10pt, lang: "en")
#set par(justify: false, leading: 0.55em)
#set page(
  paper: "a4",
  margin: (x: 1.6cm, top: 2.2cm, bottom: 2.1cm),
  header: {
    set text(size: 8.5pt)
    grid(columns: (1fr, auto), align: (left + horizon, right + horizon), column-gutter: 6pt,
      [Cyber threat report · #d.period.month · #d.document.id],
      { if marked { marktag; h(4pt) }; tlp })
    v(-3pt)
    line(length: 100%, stroke: 0.4pt + gray)
  },
  footer: context {
    set text(size: 7.5pt, fill: luma(70))
    line(length: 100%, stroke: 0.4pt + gray)
    v(-3pt)
    grid(columns: (auto, 1fr, auto), column-gutter: 10pt, align: (left + horizon, left + horizon, right + horizon),
      tlp,
      [Generated #short(d.generated_at) (Amsterdam) · data sha256 #raw(d.data_sha.slice(0, 12))#if marked [ · *#mark*]],
      [Page #counter(page).display() / #counter(page).final().first()])
  },
  background: if marked {
    rotate(-35deg, text(size: 96pt, weight: "bold", fill: rgb(176, 0, 32, 22))[#mark])
  },
)
#set table(stroke: 0.4pt + luma(170), inset: (x: 4pt, y: 3pt))
#show table: set text(size: 8.5pt)
#show heading.where(level: 1): set text(size: 13pt)
#show heading.where(level: 1): set block(above: 1.1em, below: 0.6em)
#show heading.where(level: 2): set text(size: 11pt)
#show heading.where(level: 2): set block(above: 0.9em, below: 0.45em)
#show heading.where(level: 3): set block(above: 0.8em, below: 0.4em)
#show link: set text(fill: rgb("#1a4f8b"))

#let none-row = emph[None.]
#let maybe-table(items, cols, head, f) = if items.len() == 0 { none-row } else {
  table(columns: cols, table.header(..head.map(strong)), ..items.map(f).flatten())
}
#let notice(fill, stroke, body) = block(fill: fill, stroke: 0.6pt + stroke, inset: (x: 6pt, y: 4pt), width: 100%, below: 0.5em, text(size: 9pt, body))

// ================================================================== page 1
#text(size: 17pt, weight: "bold")[#d.title]
#v(-8pt)
#text(size: 10.5pt)[#d.subtitle] \
#text(size: 9pt, fill: luma(60))[Period #d.period.text · generated #short(d.generated_at) (Europe/Amsterdam) · tickets as of #short(d.tickets_as_of)]

#if marked {
  notice(rgb("#fde7ea"), rgb("#B00020"))[*#mark* – #d.marking.notice]
}
#if d.coverage.partial {
  notice(rgb("#fff4d6"), rgb("#c58a00"))[*Partial history* – records start on #short(d.coverage.from)#[;] figures before that moment are incomplete.]
}

// ------------------------------------------------------------------ status and bottom line
#let rag = d.status.rag
#block(stroke: 0.8pt + rag-fill.at(rag), inset: 7pt, width: 100%, radius: 2pt, below: 0.8em)[
  #grid(columns: (auto, 1fr), column-gutter: 10pt, align: (center + horizon, left + horizon),
    box(fill: rag-fill.at(rag), inset: (x: 8pt, y: 6pt), radius: 2pt)[
      #set align(center)
      #text(fill: white, size: 7.5pt)[OVERALL STATUS] \
      #text(fill: white, size: 15pt, weight: "bold")[#rag]
    ],
    d.bottom_line.join(" "),
  )
]

// ------------------------------------------------------------------ attention
== Attention / decisions needed
#if d.attention.len() == 0 [
  #if mtd [None so far this month.] else [None this month.]
] else {
  set text(size: 9.5pt)
  list(..d.attention.map(a => [#text(fill: rag-fill.at(a.rag), weight: "bold", size: 8pt)[#a.rag] #a.text]))
}

// ------------------------------------------------------------------ KPIs
== Key figures
#let status-cell(s) = if s == "—" { [—] } else {
  table.cell(fill: rag-tint.at(s))[#text(fill: rag-fill.at(upper(s)), weight: "bold")[#s]]
}
// A target that is not agreed yet carries a note under it.
#let target-cell(k) = if k.target_note == none { k.target } else [#k.target \ #text(size: 7pt, fill: luma(60))[#k.target_note]]
#table(columns: (1fr, auto, auto, auto, auto),
  align: (left, left, left, left, left),
  table.header([*Measure*], [*This period*], [*Target*], [*Status*], [*vs #d.previous.label*]),
  ..d.kpis.map(k => (k.label, k.value, target-cell(k), status-cell(k.status), k.previous)).flatten())

// ------------------------------------------------------------------ open actions
== Open actions and plans
#if d.open_actions.items.len() == 0 [
  No open actions: nothing is waiting on fairCT.
] else {
  table(columns: (auto, 1fr, auto, auto, auto, auto, auto, auto),
    table.header([*Ticket*], [*Vulnerability*], [*Component*], [*Exploited*], [*Severity*], [*Owner*], [*Due*], [*Status*]),
    ..d.open_actions.items.map(i => {
      let f = if i.overdue { rgb("#fbe3e6") } else { none }
      (
        table.cell(fill: f, ticket(i)),
        table.cell(fill: f)[#i.vulnerability \ #text(size: 7.5pt, fill: luma(60), cut(i.title, 60))],
        table.cell(fill: f, dash(i.component)),
        table.cell(fill: f, if i.exploited [*yes* \ #text(size: 7.5pt, i.exploited_source)] else [no]),
        table.cell(fill: f, sev(i)),
        table.cell(fill: f, if i.owner == "" [*none*] else { i.owner }),
        table.cell(fill: f, if i.due == "" [*none*] else if i.overdue [*#i.due* \ #text(size: 7.5pt, fill: rgb("#b00020"), weight: "bold")[OVERDUE]] else { i.due }),
        table.cell(fill: f, dash(i.state_name)),
      )
    }).flatten())
}

// ------------------------------------------------------------------ resolved
== Resolved in the period
#if d.resolved.len() == 0 [
  Nothing was resolved in the period.
] else {
  set text(size: 9.5pt)
  list(..d.resolved.map(r => [#ticket(r) · #r.vulnerability (#cut(r.title, 50)) — #r.outcome#if r.warn and r.outcome.ends-with("no reason given") [ #warn]]))
}

// ------------------------------------------------------------------ coverage
#v(0.4em)
#block(fill: luma(244), inset: 6pt, width: 100%, text(size: 8.5pt)[*Coverage.* #d.monitoring.sentence])

// ================================================================== detail
#pagebreak(weak: true)
= Detail

== Assessment funnel
#let f = d.funnel
#let stage(n, l) = box(stroke: 0.4pt + luma(150), inset: (x: 5pt, y: 4pt), radius: 2pt)[
  #align(center)[#text(size: 13pt, weight: "bold", if type(n) == content { n } else { thou(n) }) \ #text(size: 7.5pt, l)]]
#let arrow = text(size: 12pt, fill: luma(110))[→]
#grid(columns: (1fr, auto, 1fr, auto, 1fr, auto, 1fr, auto, 1.3fr), column-gutter: 3pt, align: horizon,
  stage(f.notices, [new public notices]), arrow,
  stage(f.auto_ruled_out, [automatically ruled out]), arrow,
  stage(f.relevant, [relevant to fairCT]), arrow,
  stage(f.assessed, [assessed]), arrow,
  stage([#f.action_planned / #f.ruled_out_by_person / #f.waiting], [action planned / ruled out by a person / waiting]),
)

Time to assess (Amsterdam business hours, Monday–Friday, from first seen to the decision in the tracker), #f.time_to_assess.count items: median #num(f.time_to_assess.median_business_hours) h, maximum #num(f.time_to_assess.max_business_hours) h. Target: within 1 business day (24 business hours).

=== Over 1 business day
#maybe-table(f.over_one_day, (auto, auto, 1fr, auto, auto, auto),
  ([Ticket], [Vulnerability], [Title], [First seen], [Assessed], [Business h]),
  i => (ticket(i), i.vulnerability, cut(i.title, 60), short(i.first_seen),
        if i.assessed_at == none [*not yet*] else { short(i.assessed_at) }, num(i.business_hours)))

=== By source
#maybe-table(f.by_source, (1fr, auto, auto, auto),
  ([Source], [Notices], [Relevant to fairCT], [Automatically ruled out]),
  s => (s.source, thou(s.total), thou(s.relevant), thou(s.auto_ruled_out)))

== Fixed in the period
#let o = d.outcomes
#maybe-table(o.fixed, (auto, auto, 1fr, auto, auto, auto, auto),
  ([Ticket], [Vulnerability], [Title], [Owner], [Due], [Fixed], [By due date]),
  i => (ticket(i), i.vulnerability, cut(i.title, 60), dash(i.owner), dash(i.due), short(i.closed_at),
        if i.on_time == none [no due date] else if i.on_time [on time] else [*late*]))
#if o.fixed_count > 0 [
  #o.fixed_count fixed: #o.on_time on time, #o.late late, #o.no_due without a due date. Median time to fix (first seen to fixed): #num(o.mttr_median_days) days.
]

== Closed without fix
#maybe-table(o.closed_without_fix, (auto, auto, 1fr, auto, auto),
  ([Ticket], [Vulnerability], [Title], [Owner], [Closed]),
  i => (ticket(i), i.vulnerability, cut(i.title, 60), dash(i.owner), short(i.closed_at)))

== Ruled out by a person
#maybe-table(o.ruled_out, (auto, auto, 1fr, auto, 1fr, auto),
  ([Ticket], [Vulnerability], [Title], [By], [Reason], [When]),
  i => (ticket(i), i.vulnerability, cut(i.title, 50), dash(i.actor),
        if i.reason == "" [*no reason given* #warn] else { cut(i.reason, 140) }, short(i.declined_at)))

== Exceptions
#let ex = d.exceptions
#let idlist(xs) = if xs.len() == 0 { none-row } else {
  list(..xs.map(x => [#if x.identifier != "" [#x.identifier: ]#cut(x.title, 100)]))
}
#set text(size: 9.5pt)
*Overdue actions* (#ex.overdue.len()): #idlist(ex.overdue)

*Open actions without an owner* (#ex.open_without_owner.len()): #idlist(ex.open_without_owner)

*Open actions without a due date* (#ex.open_without_due.len()): #idlist(ex.open_without_due)

*Relevant items not assessed after more than 1 business day* (#ex.unassessed_over_one_day.len()): #idlist(ex.unassessed_over_one_day)

*Ruled out by a person without a reason* (#ex.declined_without_reason.len()): #idlist(ex.declined_without_reason)

*Assessed without a recorded person* (#ex.triaged_without_actor.len()): #idlist(ex.triaged_without_actor)

*Sources not healthy in the last run* (#ex.sources_unhealthy.len()):
#if ex.sources_unhealthy.len() == 0 { none-row } else {
  list(..ex.sources_unhealthy.map(s => [#s.feed: #s.status]))
}

*Ticket tracker errors in the period* (#ex.tracker_errors.len()):
#if ex.tracker_errors.len() == 0 { none-row } else {
  table(columns: (auto, 1fr), table.header([*Run*], [*Error*]),
    ..ex.tracker_errors.map(e => (short(e.run_at), text(size: 8pt, e.error))).flatten())
}
#if ex.log_lines_skipped > 0 [
  *Unreadable event log lines skipped:* #ex.log_lines_skipped.
]

// ================================================================== appendix
#set text(size: 10pt)
#pagebreak(weak: true)
= Appendix (audit)

== Report provenance
#table(columns: (auto, 1fr), stroke: none, inset: (x: 0pt, y: 2.5pt), column-gutter: 10pt,
  [*Period*], [#short(d.period.start) to #short(d.period.end) (Europe/Amsterdam; end excluded)#if not d.period.complete [; figures to #short(d.period.data_to)]],
  [*Generated*], [#short(d.generated_at)],
  [*Tickets as of*], [#short(d.tickets_as_of) (last read-back from the tracker included)],
  [*History covers from*], [#short(d.coverage.from)#if d.coverage.partial [ (after the period start: partial)]#[;] #thou(d.coverage.duplicates_dropped) repeated events dropped#if d.coverage.half_written_tail [; a half-written last line skipped]#if d.coverage.backfilled > 0 [; risk fields of #thou(d.coverage.backfilled) older decisions taken from triage.json]],
  [*Component list*], [#if d.component_list.version == "" [—] else [#d.component_list.version#if d.component_list.count != none [ (#d.component_list.count components)], sha256 #raw(d.component_list.sha256)]#if d.components.len() > 1 [; decisions in the period: #d.components.map(c => [#c.version (#c.decisions)]).join([, ])]],
  [*Tracker*], [#dash(d.tracker.endpoint)#if marked [ — *#mark*]],
  [*Scheduled runs*], [#d.runs.writing#if d.runs.writing > 0 [ (#d.runs.by_result.pairs().map(((k, v)) => [#k #v]).join([, ]))]],
  [*Data sha256*], [#raw(d.data_sha)],
  [*Source files*], [`triage-events.jsonl` (event log), `runs.jsonl` (run log), `triage.json` (item copies for older decisions); output `report.json`, `report.pdf`, `SHA256SUMS`],
)

=== Feed health (last scheduled run of the period)
#maybe-table(d.feeds, (1fr, auto, auto, 2fr, auto),
  ([Source], [Runs], [OK], [By status], [Last run]),
  f => (f.feed, str(f.runs), str(f.ok), f.by_status.pairs().map(((k, v)) => k + " " + str(v)).join(", "),
        if f.healthy { f.last_status } else { strong(f.last_status) }))
#if d.feeds_removed.len() > 0 [
  Removed during the period: #d.feeds_removed.join(", ").
]

// Monthly close only (close.rs): the random sample of automatically ruled-out items.
#let rs = d.at("review_sample", default: none)
#if rs != none [
== Quality check sample — automatically ruled-out items
  #set text(size: 9pt)
  A control for the automatic rule-out, which matches by component name only and does not check affected versions: #rs.items.len() of #thou(rs.candidates) items ruled out automatically in the period, drawn at random before this report was frozen (seed sha256 #raw(rs.seed.slice(0, 16))…, reproducible from the event log). The review reminder in the ticket tracker asks a person to check each one; an item found relevant is reported there, so that the component list can be completed.

  #if rs.items.len() == 0 {
    emph(if rs.note == "" { "No automatically ruled-out items in the period." } else { rs.note })
  } else {
    table(columns: (auto, auto, 1fr, auto),
      table.header([*No.*], [*Item*], [*Title*], [*Vendor / product*]),
      ..rs.items.enumerate().map(((n, i)) => (
        str(n + 1),
        if i.url == "" { text(size: 7.5pt, i.key) } else { link(i.url, text(size: 7.5pt, i.key)) },
        if i.title == "" { "—" } else { cut(i.title, 90) },
        dash(i.vendor_product),
      )).flatten())
  }
]

== Definitions
#set text(size: 8.5pt)
- *Source of the figures*: the append-only event log of Exploit Watch and its run log. Events are placed at the time the tracker gives (when the ticket was triaged, completed or canceled), not when they were logged; repeated events are counted once.
- *New public vulnerability notice*: an item first seen by the job in the period, from any monitored source. *Automatically ruled out*: no component on fairCT's list matches it (decided by rule). *Relevant to fairCT*: it matches a listed component; a ticket is filed.
- *Assessed*: a person decided on the ticket in the tracker: *action planned* (accepted) or *ruled out by a person* (declined, with a reason). Counted for the items relevant in the period, whenever the decision came. *Time to assess* counts Monday to Friday in Europe/Amsterdam time, no holiday calendar.
- *Open action*: accepted and not closed at the end of the period; the owner and due date are the plan. *Overdue*: due date before the end of the period. *Fixed*: done in the tracker; *on time* when closed on or before the due date (Amsterdam date). *Closed without fix*: accepted, then canceled.
- *Known exploited*: the item comes from the CISA Known Exploited Vulnerabilities catalog or ENISA EUVD's exploited list, its CVE.org record has CISA's SSVC "Exploitation: active", or one of its CVEs was seen in CISA KEV or ENISA EUVD by the end of the period.
- *Sources healthy*: sources fetched in the last scheduled run of the period, or read from the job's cache within their polling interval; *stale* or *failing* means the fetch failed.
- *KPIs*: assessed within 1 business day = assessments within 24 business hours ÷ (assessments + items waiting longer), target 100%; open actions and overdue, target 0 overdue; fixed by due date = fixes on or before the due date ÷ fixes in the period (the metric "remediation by due date" as defined in NIST SP 800-40r4, Table 1, like the median time to fix, "time to remediate"; NIST sets no target), target ≥ 95%, a team proposal pending agreement with fairCT; known-exploited items still open, target 0 overdue; sources healthy, target all. Recording and monitoring of ICT-related threats follow RTS (EU) 2024/1774, Art. 10. *vs previous month* is the same measure for the previous calendar month when the event log covers it, else "first period".
- *Overall status* is the worst of the rules below (team proposal, 2026-11-05). *GREEN*: every relevant item assessed within 1 business day, no overdue action, every open action has an owner and a due date, all sources healthy in the last run, no tracker error in the period, at least 95% of fixes by their due date. *AMBER*, any of: an assessment took (or an item has waited) more than 1 business day; an open action lacks an owner or a due date; ruled out by a person without a reason; a source stale or failing in the last run, or no scheduled run in the period; a tracker error in the period; an overdue action on an item not known to be exploited; fewer than 95% of the fixes in the period by their due date. *RED*, any of: an overdue action on a known-exploited item; a relevant item not assessed for more than 3 business days at the end of the period; a core source (CISA KEV or CVE.org) failing for more than 2 days.
- *Data sha256* is the sha256 of report.json without its generation time: two reports with equal data have equal values. This report implements requirement FR-A4 (resolution report to the fairCT COO).

#set text(size: 10pt)
#block(breakable: false)[
== Document control
#table(columns: (auto, 1fr), inset: (x: 5pt, y: 3pt),
  [*Document ID*], [#d.document.id],
  [*Version*], [#d.document.version],
  [*Status*], [#d.document.status],
  [*Prepared by*], [#d.document.prepared_by],
  [*Reviewed by*], [#box(width: 5cm, repeat[\_]) (date #box(width: 2.2cm, repeat[\_]))],
  [*Acknowledged by the fairCT COO*], [#box(width: 5cm, repeat[\_]) (date #box(width: 2.2cm, repeat[\_]))],
  [*Distribution*], [#d.document.distribution],
  [*Retention*], [#d.document.retention],
  [*Integrity*], [data sha256 #raw(d.data_sha)#[;] SHA256SUMS next to the file],
)
]