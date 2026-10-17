---
title: Changes
description: "Every revision made to a published report, newest first: what changed, by section, and when. Also as an Atom feed and a JSON Feed."
layout: page
permalink: /changes/
---

<div class="hl-page-header" style="--ph-accent: #a371f7;">
  <div class="hl-page-header__label">Changes</div>
  <div class="hl-page-header__title">Revisions to published reports</div>
  <div class="hl-page-header__desc">A report that was revised after it went out says so, and says what changed. This page collects those notes in one place, newest first, so you can see what moved without rereading every report. Follow it as an <a href="/changes/feed.xml">Atom feed</a> or a <a href="/changes/feed.json">JSON Feed</a>.</div>
</div>

{%- include changes-items.liquid -%}

{% if changes_items.size > 0 %}
<ol class="hl-changes" data-pagefind-ignore>
{%- for rec in changes_items %}
{%- assign f = rec | split: "~~" %}
<li class="hl-changes__item"><time datetime="{{ f[0] }}">{{ f[0] | date: "%-d %B %Y" }}</time> <a href="{{ f[1] }}#revisions">{{ f[3] | escape }}</a><span class="hl-changes__note"> {{ f[4] | escape }}</span></li>
{%- endfor %}
</ol>
{% else %}
No revisions have been recorded yet.
{% endif %}

{% if changes_unitemised.size > 0 %}
## Revised before revision notes were kept

{{ changes_unitemised.size }} older report{% if changes_unitemised.size != 1 %}s were{% else %} was{% endif %} revised before revision lists were kept, so the date of the last revision is all that was recorded. Each report's own revision note says the same.

<ul class="hl-changes hl-changes--bare" data-pagefind-ignore>
{%- for rec in changes_unitemised %}
{%- assign f = rec | split: "~~" %}
<li class="hl-changes__item"><time datetime="{{ f[0] }}">{{ f[0] | date: "%-d %B %Y" }}</time> <a href="{{ f[1] }}#revisions">{{ f[3] | escape }}</a></li>
{%- endfor %}
</ul>
{% endif %}
