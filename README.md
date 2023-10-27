# What's all this then?

`dot-iptables.py` reads the output of `iptables-save` and then
generates a [dot][] graph showing the relationship between chains in your
iptables configuration, with clickable chain names to see the rules in
the given chain.

## Usage

    sudo iptables-save | python3 -m dotiptables --render --outputdir /SOME/PATH/
    $BROWSER /SOME/PATH/index.html

Be sure to have Graphviz and Python's Jinja2 installed.

[dot]: http://www.graphviz.org/

