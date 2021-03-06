---
layout: default
---

<h1> Welcome to my Blog! </h1>

<h3>This is a place where I post writeups to the some of the CTF's and wargames I solve. My favourite challenges are those related to Reverse Engineering and Exploit Development so most of the posts here will revolve around these two topics.</h3>
<br>
<br>
<h1>Latest Posts</h1>
<ul>
  {% for post in site.posts %}
    <li>
      <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
    </li>
  {% endfor %}
</ul>
