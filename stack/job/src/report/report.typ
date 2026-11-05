// FR-A4 resolution report. Compiled by report/pdf.rs with data.json (report.json
// plus data_sha) next to it; only typst's embedded fonts are used.
#let d = json("data.json")
#let lab = d.tracker.lab_data
#let tlp = box(fill: black, inset: (x: 4pt, y: 2.5pt), radius: 1pt,
  text(fill: rgb("#FFC000"), weight: "bold", font: "DejaVu Sans Mono", size: 8pt)[TLP:AMBER+STRICT])
#let labtag = box(fill: rgb("#B00020"), inset: (x: 4pt, y: 2.5pt), radius: 1pt,
  text(fill: white, weight: "bold", font: "DejaVu Sans Mono", size: 8pt)[LAB DATA])

// Times in data.json are Amsterdam local with offset: show "YYYY-MM-DD HH:MM".
#let short(t) = if t == none { "–" } else { t.slice(0, 16).replace("T", " ") }
#let day(t) = if t == none { "–" } else { t.slice(0, 10) }
#let dash(s) = if s == none or s == "" { "–" } else { str(s) }
#let num(x) = if x == none { "–" } else { str(x) }
#let cut(s, n) = {
  let c = s.clusters()
  if c.len() > n { c.slice(0, n).join() + "…" } else { s }
}
#let ticket(i) = if i.identifier == "" { text(size: 7.5pt, i.key) } else { link(i.url, i.identifier) }

#set document(title: d.label, author: "Exploit Watch (fairCT)")
#set text(font: "Libertinus Serif", size: 9.5pt, lang: "en")
#set par(justify: false)
#set page(
  paper: "a4",
  margin: (x: 1.7cm, top: 2.4cm, bottom: 2.2cm),
  header: {
    set text(size: 8.5pt)
    grid(columns: (1fr, auto), align: (left + horizon, right + horizon), column-gutter: 6pt,
      d.label,
      { if lab { labtag; h(4pt) }; tlp })
    v(-4pt)
    line(length: 100%, stroke: 0.4pt + gray)
  },
  footer: context {
    set text(size: 7.5pt, fill: luma(80))
    line(length: 100%, stroke: 0.4pt + gray)
    v(-4pt)
    grid(columns: (1fr, auto, auto), column-gutter: 14pt,
      [Generated #short(d.generated_at) (Europe/Amsterdam) · data sha256 #raw(d.data_sha.slice(0, 12))],
      if lab [*LAB DATA*] else [],
      [Page #counter(page).display() / #counter(page).final().first()])
  },
  background: if lab {
    rotate(-35deg, text(size: 96pt, weight: "bold", fill: rgb(176, 0, 32, 22))[LAB DATA])
  },
)
#set table(stroke: 0.4pt + luma(170), inset: (x: 4pt, y: 3pt))
#show heading.where(level: 1): set block(above: 1.3em, below: 0.6em)
#show heading.where(level: 2): set block(above: 1em, below: 0.5em)
#show link: set text(fill: rgb("#1a4f8b"))

#let none-row = emph[None.]
#let maybe-table(items, cols, head, f) = if items.len() == 0 { none-row } else {
  table(columns: cols, table.header(..head.map(strong)), ..items.map(f).flatten())
}

// ------------------------------------------------------------------ title
#text(size: 17pt, weight: "bold")[Cyber threat report]
#v(-6pt)
#text(size: 12pt)[#d.label]

#if lab [
  #block(fill: rgb("#fde7ea"), stroke: 0.6pt + rgb("#B00020"), inset: 6pt, width: 100%)[
    *LAB DATA.* The tracker is the local `linear-mock` (#d.tracker.endpoint): tickets, owners and dates are test data, not fairCT's.
  ]
]
#if d.coverage.partial [
  #block(fill: rgb("#fff4d6"), stroke: 0.6pt + rgb("#c58a00"), inset: 6pt, width: 100%)[
    *History covers from #short(d.coverage.from).* The event log starts then, so counts for the period before that moment are incomplete.
  ]
]
#if not d.period.complete [
  #block(fill: luma(240), inset: 6pt, width: 100%)[
    The period is not over: figures run to #short(d.period.data_to).
  ]
]

#table(columns: (auto, 1fr), stroke: none, inset: (x: 0pt, y: 2.5pt), column-gutter: 10pt,
  [*Period*], [#short(d.period.start) to #short(d.period.end) (Europe/Amsterdam; end excluded)],
  [*Generated*], [#short(d.generated_at)],
  [*Tickets as of*], [#short(d.tickets_as_of) (last read-back from the tracker included)],
  [*History covers from*], [#short(d.coverage.from)],
  [*Component list*], [#if d.components.len() == 0 [no decisions in the period] else {
    d.components.map(c => [#c.version (sha256 #raw(c.sha256.slice(0, calc.min(12, c.sha256.len()))), #c.decisions decisions)]).join([; ])
  }],
  [*Tracker*], [#dash(d.tracker.endpoint)#if lab [ — *LAB DATA*]],
  [*Job runs*], [#d.runs.writing writing runs#if d.runs.writing > 0 [ (#d.runs.by_result.pairs().map(((k, v)) => [#k #v]).join([, ]))]],
  [*Data sha256*], [#raw(d.data_sha)],
  [*Distribution*], [#tlp internal to fairCT: the COO and those who need it; no external sharing],
)

== Summary
#let kpi(n, l) = box(width: 100%, stroke: 0.4pt + luma(170), inset: 5pt)[
  #align(center)[#text(size: 15pt, weight: "bold", str(n)) \ #text(size: 8pt, l)]]
#grid(columns: (1fr,) * 6, column-gutter: 5pt,
  kpi(d.intake.total, [items assessed]),
  kpi(d.triage.matched, [matched]),
  kpi(d.triage.triaged.total, [triaged]),
  kpi(d.triage.untriaged_at_end, [untriaged at end]),
  kpi(d.actions_taken.done_count, [done]),
  kpi(d.actions_open.count, [open (#d.actions_open.overdue overdue)]),
)

== Feed health (writing runs in the period)
#maybe-table(d.feeds, (1fr, auto, auto, 2fr, auto),
  ([Feed], [Runs], [OK], [By status], [Last]),
  f => (f.feed, str(f.runs), str(f.ok), f.by_status.pairs().map(((k, v)) => k + " " + str(v)).join(", "), f.last_status))

= Intake
Items first seen in the period, as decided by the matcher.
#maybe-table(d.intake.by_source, (1fr, auto, auto, auto),
  ([Source], [Items], [Matched], [Not relevant]),
  s => (s.source, str(s.total), str(s.matched), str(s.not_relevant)))
#if d.intake.by_source.len() > 0 [Total #d.intake.total: #d.intake.matched matched, #d.intake.not_relevant not relevant by rule.]

= Triage (FR-A2)
#table(columns: (1fr, auto),
  table.header([*Measure*], [*Count*]),
  [Not relevant by rule (decided by the matcher, first seen in the period)], str(d.triage.auto_not_relevant),
  [Matched (first seen in the period)], str(d.triage.matched),
  [Triaged in Linear in the period (any first-seen date)], str(d.triage.triaged.total),
  [#h(1em) accepted], str(d.triage.triaged.accepted),
  [#h(1em) declined with a reason], str(d.triage.triaged.declined_with_reason),
  [#h(1em) declined without a reason], str(d.triage.triaged.declined_without_reason),
  [Untriaged at the end of the period], str(d.triage.untriaged_at_end),
)
Time to triage (Amsterdam business hours, Monday–Friday, from first seen to the triage in Linear), #d.triage.time_to_triage.count items:
median #num(d.triage.time_to_triage.median_business_hours) h, max #num(d.triage.time_to_triage.max_business_hours) h. Target: within one business day (24 business hours).

=== Over one business day
#maybe-table(d.triage.sla_breaches, (auto, 1fr, auto, auto, auto),
  ([Ticket], [Title], [First seen], [Triaged], [Business h]),
  i => (ticket(i), cut(i.title, 110), short(i.first_seen),
        if i.triaged_at == none [*not yet*] else { short(i.triaged_at) }, str(i.business_hours)))

= Actions taken
== Done in the period
#maybe-table(d.actions_taken.done, (auto, 1fr, auto, auto, auto, auto, auto),
  ([Ticket], [Title], [Component], [Owner], [Due], [Closed], [On time]),
  i => (ticket(i), cut(i.title, 90), dash(i.component), dash(i.owner), dash(i.due), short(i.closed_at),
        if i.on_time == none [no due date] else if i.on_time [yes] else [*no*]))
#if d.actions_taken.done_count > 0 [
  #d.actions_taken.done_count done: #d.actions_taken.on_time on time, #d.actions_taken.late late, #d.actions_taken.no_due without a due date.
  Median time to resolve (first seen to done): #num(d.actions_taken.mttr_median_days) days.
]

== Canceled after acceptance
#maybe-table(d.actions_taken.canceled, (auto, 1fr, auto, auto, auto),
  ([Ticket], [Title], [Component], [Owner], [Canceled]),
  i => (ticket(i), cut(i.title, 100), dash(i.component), dash(i.owner), short(i.closed_at)))

== Declined in the period
#maybe-table(d.actions_taken.declined, (auto, 1fr, auto, 1fr, auto),
  ([Ticket], [Title], [By], [Reason], [Declined]),
  i => (ticket(i), cut(i.title, 80), dash(i.actor),
        if i.reason == "" [*no reason given*] else { cut(i.reason, 160) }, short(i.declined_at)))

= Actions open (with plans)
Tickets accepted and not closed at #short(d.period.data_to): the owner and due date are the plan.
#maybe-table(d.actions_open.items, (auto, 1fr, auto, auto, auto, auto, auto),
  ([Ticket], [Title], [Component], [Owner], [Due], [Status], [Age (d)]),
  i => (ticket(i), cut(i.title, 90), dash(i.component),
        if i.owner == "" [*no owner*] else { i.owner },
        if i.due == "" [*no due date*] else if i.overdue [*#i.due (overdue)*] else { i.due },
        dash(i.state_name), num(i.age_days)))

= Exceptions
#let ex = d.exceptions
#let idlist(xs) = if xs.len() == 0 { none-row } else {
  list(..xs.map(x => [#if x.identifier != "" [#x.identifier: ]#cut(x.title, 120)]))
}
*Open tickets without an owner* (#ex.open_without_owner.len()): #idlist(ex.open_without_owner)

*Open tickets without a due date* (#ex.open_without_due.len()): #idlist(ex.open_without_due)

*Declined without a reason* (#ex.declined_without_reason.len()): #idlist(ex.declined_without_reason)

*Triaged without a recorded actor* (#ex.triaged_without_actor.len()): #idlist(ex.triaged_without_actor)

*Tracker errors in the period* (#ex.tracker_errors.len()):
#if ex.tracker_errors.len() == 0 { none-row } else {
  table(columns: (auto, 1fr), table.header([*Run*], [*Error*]),
    ..ex.tracker_errors.map(e => (short(e.run_at), text(size: 8pt, e.error))).flatten())
}
#if ex.log_lines_skipped > 0 [
  *Unreadable event log lines skipped:* #ex.log_lines_skipped.
]

= Definitions
#set text(size: 8.5pt)
- Source: the append-only triage event log of Exploit Watch (`triage-events.jsonl`) and its run log (`runs.jsonl`). Events are placed at the time the tracker gives (Linear `triagedAt`, `completedAt`, `canceledAt`), not when they were logged; repeated events are counted once.
- *Triaged* counts an item in the period of its first triage in Linear. *Declined with a reason* uses the reason known at the end of the period. *Untriaged* means matched and still in Linear's Triage inbox (or not filed yet).
- *Time to triage* counts Monday to Friday in Europe/Amsterdam time, no holiday calendar, as on the dashboard.
- *On time*: closed on or before the due date (Amsterdam date). *Overdue*: due date before the end of the period. *Age*: days since the ticket was filed.
- *Canceled after acceptance* is a ticket accepted, then canceled in Linear; it is closed, not declined.
- *Data sha256* is the sha256 of report.json without its `generated_at`: two reports with equal data have equal values.
