---
layout: default
title: OverTheWire
permalink: /overthewire/index.html
---

<ul>
  {% for post in site.posts %}
    {% if post.categories contains "overthewire" %}
        <li>
            <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
        </li>
    {% endif %}
  {% endfor %}
</ul>