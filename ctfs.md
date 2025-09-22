---
layout: page
title: CTFs
permalink: /ctfs/
---


<ul class="post-list">
  {% for ctf in site.ctfs %}
    <li>
      {% assign date_format = site.minima.date_format | default: "%b %-d, %Y" %}
      <span class="post-meta">{{ ctf.date | date: date_format }}</span>
      <h3>
        <a class="post-link" href="{{ ctf.url | relative_url }}">
          {{ ctf.title | escape }}
        </a>
      </h3>
    </li>
  {% endfor %}
</ul>

