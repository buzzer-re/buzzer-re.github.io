---
title: "Using bipartite Graphs to detect Malware campaigns"
date: 2020-04-30 20:31:36 -0300

categories: [Malware-Research]
tags: [Programming, Malware Research]

images_prefix: /assets/images/bipartite_graph/
---

One of the greatest problems in mapping threats today, is detect from where it's came, if is from the same group, same person or even from the same governament. 

In order to group everything up and make things more clear, we can use a lot of data structures for that, a good one, and very famous is a Graph, a Biptartite Graph more exactly.

In order to acomplish that, I wrote a simple [Python code](https://github.com/AandersonL/mresearch/blob/master/malware_research/bipartite_graph/mal_vis.py) to map all domains that is possible to find in a large dataset of PE files.

This code was inspired in the [Malware Data Science](https://nostarch.com/malwaredatascience) book, and uses an [Bipartite Graph](https://en.wikipedia.org/wiki/Bipartite_graph) to build two sets, Domains and Samples, and the connect each one.


## Bipartite Graph

![](/assets/images/using_bipartide_graphs/bipartite.jpg)

Bipartite graph is a graph where the vertices(nodes) can be splited in two groups and be connected to each other, that way, each vertice can have multiple connections to an specific set and can be used to determine how many nodes in a give group has an relation in another group.

In this code, i extracted all samples strings of a given path, and applied a regex rule to extract possible domain names + loaded a valid [domain suffixes](domain_suffixes.txt) to create an valid dictionary to extract only correct domains from the samples.


```python
# Yep, i'm using strings here
strs = subprocess.check_output(["strings", abs_dir]).decode()
hosts = extract_hostnames(strs, compiled_rule, valid_domains)

if len(hosts) > 0:
    # Build graph
    network.add_node(path, label=path[:32], color='black', penwidth=5, bipartite=0) # <- This put our sample in set 1
    for hostname in hosts:
        network.add_node(hostname, label=hostname, color='blue', penwidth=10, bipartite=1) # <- This put our hostname in set 2
        network.add_edge(hostname, path)
```

With that is possible to create an ***set of domains*** and a ***set of samples***, and then connect each sample to a given domain and find which samples shares the same domain, thus, find and classify possible malware campaigns or a set of malware controlled by the same C2/group.


## Domain graph of [APT1](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf)

![](/assets/images/using_bipartide_graphs/malware_domains_apt1.png)




## Executing

```
$ pip install -r requirements.txt
$ python mal_vis.py --target_path <path_to_samples>
```

This will generate a [DOT](https://www.graphviz.org/doc/info/lang.html) file that you can further import in any [graphviz](https://www.graphviz.org/) tool.


Again, all thanks to [Malware Data Science](https://nostarch.com/malwaredatascience).

