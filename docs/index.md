---
layout: home
title: OSEP Notes
titleTemplate: Operator field manual

hero:
  name: OSEP / FIELD MANUAL
  text: Technical notes for constrained operations
  tagline: A scenario-driven reference for execution, privilege, movement, and evidence in authorized OSEP environments.
  actions:
    - theme: brand
      text: Open scenario map
      link: /scenarios
    - theme: alt
      text: Establish the lab baseline
      link: /modules/00-environment-and-infra

features:
  - title: M01–M05 · Execution constraints
    details: Office, HTA, JScript, DLL sideloading, AppLocker, CLM, and AMSI paths.
    link: /modules/01-word-vba-office
    linkText: Start with execution
  - title: M06–M15 · Identity & movement
    details: Privilege, credentials, egress, pivoting, services, directory attacks, Linux, and lateral access.
    link: /modules/06-uac-windows-privesc
    linkText: Trace the attack path
  - title: M97–M99 · Exam operations
    details: Field lookup, evidence-ready notes, and the pre-exam readiness checklist.
    link: /modules/97-exam-day-lookup
    linkText: Open exam references
---

<div class="home-workflow" aria-label="Operating loop">
  <p>OPERATING LOOP</p>
  <ol>
    <li><strong>01</strong><span>Observe the constraint</span></li>
    <li><strong>02</strong><span>Verify the reachable path</span></li>
    <li><strong>03</strong><span>Change one variable</span></li>
    <li><strong>04</strong><span>Record the evidence</span></li>
  </ol>
</div>

## Start from the condition, not the tool

Each module is organized around a concrete operating condition. Confirm the path you can observe, run the smallest reversible test, and preserve the result before changing another variable.

> **Authorized use only.** These notes are for the official OSEP labs and exam, your own isolated lab, or systems you have written authorization to test.
